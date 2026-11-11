use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const BOOT_IMG_MAGIC: &[u8] = b"ANDROID!";
const AVB_MAGIC: &[u8] = b"AVB0";
const VENDOR_BOOT_MAGIC: &[u8] = b"VNDRBOOT";
const BOOT_IMG_HDR_V4: u32 = 4;

pub struct AndroidGkiBootDetector;

impl Default for AndroidGkiBootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidGkiBootDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_boot_image_tampering(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if data.len() < 4096 {
            return findings;
        }

        if &data[0..8] != BOOT_IMG_MAGIC {
            return findings;
        }

        let header_version = if data.len() >= 44 {
            u32::from_le_bytes([data[40], data[41], data[42], data[43]])
        } else {
            return findings;
        };

        if header_version >= BOOT_IMG_HDR_V4 {
            let signature_size_offset = 48;
            if data.len() > signature_size_offset + 4 {
                let sig_size = u32::from_le_bytes([
                    data[signature_size_offset],
                    data[signature_size_offset + 1],
                    data[signature_size_offset + 2],
                    data[signature_size_offset + 3],
                ]);

                if sig_size == 0 {
                    findings.push(
                        Finding::new(
                            "android_gki_boot",
                            Severity::Critical,
                            "GKI boot image v4+ with zero-length signature",
                            &format!(
                                "Found Android boot image header version {} with signature_size=0. \
                                 GKI boot images must be signed for AVB verification. A zero-length \
                                 signature indicates the image has been tampered to bypass Verified Boot.",
                                header_version
                            ),
                        )
                        .with_confidence(0.94)
                        .with_details(serde_json::json!({
                            "header_version": header_version,
                            "signature_size": 0,
                            "technique": "GKI boot image signature removal for Verified Boot bypass",
                        }))
                        .with_recommendation(
                            "Reflash factory boot image; verify AVB chain of trust is intact",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_avb_hash_mismatch(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data.windows(AVB_MAGIC.len()).position(|w| w == AVB_MAGIC) {
            let region_end = (pos + 256).min(data.len());
            let region = &data[pos..region_end];

            let has_hash_descriptor = region.windows(4).any(|w| w == [0x00, 0x00, 0x00, 0x02]);
            let has_null_hash = region.len() >= 128 && region[96..128].iter().all(|&b| b == 0x00);

            if has_hash_descriptor && has_null_hash {
                findings.push(
                    Finding::new(
                        "android_gki_boot",
                        Severity::Critical,
                        "AVB vbmeta descriptor with zeroed hash value",
                        &format!(
                            "Found AVB footer at offset 0x{:08X} containing a hash descriptor \
                             with an all-zero hash value. This allows any partition content to \
                             pass AVB verification, completely defeating Android Verified Boot.",
                            pos
                        ),
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "hash_descriptor_present": true,
                        "null_hash": true,
                        "technique": "AVB hash descriptor nullification for Verified Boot bypass",
                    }))
                    .with_recommendation(
                        "Re-sign boot images with OEM key; verify vbmeta chain integrity",
                    ),
                );
            }
        }

        findings
    }

    fn check_vendor_boot_ramdisk(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(VENDOR_BOOT_MAGIC.len())
            .position(|w| w == VENDOR_BOOT_MAGIC)
        {
            let ramdisk_size_offset = pos + 16;
            if data.len() > ramdisk_size_offset + 4 {
                let ramdisk_size = u32::from_le_bytes([
                    data[ramdisk_size_offset],
                    data[ramdisk_size_offset + 1],
                    data[ramdisk_size_offset + 2],
                    data[ramdisk_size_offset + 3],
                ]);

                let total_size_offset = pos + 24;
                if data.len() > total_size_offset + 4 {
                    let page_size = u32::from_le_bytes([
                        data[total_size_offset],
                        data[total_size_offset + 1],
                        data[total_size_offset + 2],
                        data[total_size_offset + 3],
                    ]);

                    if ramdisk_size > 0 && page_size > 0 && ramdisk_size > page_size * 64 {
                        findings.push(
                            Finding::new(
                                "android_gki_boot",
                                Severity::High,
                                "Vendor boot image with oversized ramdisk (possible injection)",
                                &format!(
                                    "Found vendor_boot header at offset 0x{:08X} with ramdisk size \
                                     0x{:X} ({} MB) which exceeds expected bounds. An oversized \
                                     vendor ramdisk may contain injected modules or init scripts.",
                                    pos,
                                    ramdisk_size,
                                    ramdisk_size / (1024 * 1024)
                                ),
                            )
                            .with_confidence(0.75)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", pos),
                                "ramdisk_size": ramdisk_size,
                                "page_size": page_size,
                                "technique": "Vendor boot ramdisk injection analysis",
                            }))
                            .with_recommendation(
                                "Extract and audit vendor ramdisk contents; compare against factory image",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }
}

impl Detector for AndroidGkiBootDetector {
    fn name(&self) -> &str {
        "android_gki_boot"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_boot_image_tampering(&data));
        findings.extend(self.check_avb_hash_mismatch(&data));
        findings.extend(self.check_vendor_boot_ramdisk(&data));

        Ok(findings)
    }
}
