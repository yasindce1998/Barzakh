use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const TRUSTY_MAGIC: &[u8] = b"TRUSTY";
const LK_MAGIC: &[u8] = b"ANDROID";
const TRUSTY_LOAD_ADDR_OFFSET: usize = 16;
const SECURE_MEM_BASE: u64 = 0xB0000000;
const SECURE_MEM_END: u64 = 0xC0000000;

pub struct AndroidTrustyDetector;

impl Default for AndroidTrustyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidTrustyDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_trusty_signature_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(TRUSTY_MAGIC.len())
            .position(|w| w == TRUSTY_MAGIC)
        {
            let sig_offset = pos + 64;
            let sig_end = (sig_offset + 256).min(data.len());

            if sig_end > sig_offset {
                let sig_region = &data[sig_offset..sig_end];
                let sig_zeroed = sig_region.iter().all(|&b| b == 0x00);

                if sig_zeroed {
                    findings.push(
                        Finding::new(
                            "android_trusty",
                            Severity::Critical,
                            "Trusty OS image with zeroed signature block",
                            &format!(
                                "Found Trusty TEE image header at offset 0x{:08X} with a completely \
                                 zeroed 256-byte signature field. The Android Bootloader (ABL) must \
                                 verify Trusty's signature before loading it into secure memory. \
                                 A zeroed signature indicates the image was patched to bypass verification.",
                                pos
                            ),
                        )
                        .with_confidence(0.95)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "signature_zeroed": true,
                            "signature_size": 256,
                            "technique": "Trusty OS signature bypass via field zeroing",
                        }))
                        .with_recommendation(
                            "Reflash Trusty image from factory; verify ABL enforces signature check",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_load_address_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(TRUSTY_MAGIC.len())
            .position(|w| w == TRUSTY_MAGIC)
        {
            let addr_offset = pos + TRUSTY_LOAD_ADDR_OFFSET;
            if data.len() >= addr_offset + 8 {
                let load_addr = u64::from_le_bytes([
                    data[addr_offset],
                    data[addr_offset + 1],
                    data[addr_offset + 2],
                    data[addr_offset + 3],
                    data[addr_offset + 4],
                    data[addr_offset + 5],
                    data[addr_offset + 6],
                    data[addr_offset + 7],
                ]);

                if load_addr != 0 && !(SECURE_MEM_BASE..SECURE_MEM_END).contains(&load_addr) {
                    findings.push(
                        Finding::new(
                            "android_trusty",
                            Severity::Critical,
                            "Trusty OS load address outside secure memory region",
                            &format!(
                                "Found Trusty image at offset 0x{:08X} with load address \
                                 0x{:016X} which falls outside the expected secure memory range \
                                 (0x{:08X}-0x{:08X}). Loading Trusty outside secure memory \
                                 exposes TEE secrets to the normal world OS.",
                                pos, load_addr, SECURE_MEM_BASE, SECURE_MEM_END
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "load_address": format!("0x{:016X}", load_addr),
                            "secure_range": format!("0x{:08X}-0x{:08X}", SECURE_MEM_BASE, SECURE_MEM_END),
                            "technique": "Trusty load address manipulation for TEE data exposure",
                        }))
                        .with_recommendation(
                            "Verify Trusty load address is within TrustZone secure DRAM region",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_lk_entry_point_patch(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data.windows(LK_MAGIC.len()).position(|w| w == LK_MAGIC) {
            let entry_offset = pos + 32;
            if data.len() >= entry_offset + 8 {
                let region_end = (entry_offset + 64).min(data.len());
                let entry_region = &data[entry_offset..region_end];

                let has_branch_immediate = entry_region.windows(4).any(|w| (w[3] & 0xFC) == 0x14);
                let has_nop_sled = entry_region
                    .windows(16)
                    .any(|w| w.chunks(4).all(|c| c == [0x1F, 0x20, 0x03, 0xD5]));

                if has_branch_immediate && has_nop_sled {
                    findings.push(
                        Finding::new(
                            "android_trusty",
                            Severity::High,
                            "Trusty/LK bootloader with patched entry point (branch + NOP sled)",
                            &format!(
                                "Found LK bootloader header at offset 0x{:08X} with entry point \
                                 containing an unconditional branch instruction followed by a NOP \
                                 sled. This is characteristic of a patched Trusty image redirecting \
                                 execution to injected code.",
                                pos
                            ),
                        )
                        .with_confidence(0.87)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", pos),
                            "branch_immediate": true,
                            "nop_sled_detected": true,
                            "technique": "Trusty/LK entry point patching with NOP sled redirection",
                        }))
                        .with_recommendation(
                            "Compare Trusty binary hash against known-good factory image",
                        ),
                    );
                }
            }
        }

        findings
    }
}

impl Detector for AndroidTrustyDetector {
    fn name(&self) -> &str {
        "android_trusty"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_trusty_signature_bypass(&data));
        findings.extend(self.check_load_address_manipulation(&data));
        findings.extend(self.check_lk_entry_point_patch(&data));

        Ok(findings)
    }
}
