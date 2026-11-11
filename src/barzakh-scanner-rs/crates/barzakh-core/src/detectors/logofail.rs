use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const BMP_MAGIC: [u8; 2] = [0x42, 0x4D];
const PNG_MAGIC: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const JPEG_MAGIC: [u8; 2] = [0xFF, 0xD8];
const EFI_FV_SIGNATURE: &[u8] = b"_FVH";

pub struct LogofailDetector;

impl Default for LogofailDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LogofailDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_bmp_header(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + 54 > data.len() {
            return findings;
        }

        let file_size =
            u32::from_le_bytes(data[offset + 2..offset + 6].try_into().unwrap_or([0; 4])) as usize;
        let bi_width =
            i32::from_le_bytes(data[offset + 18..offset + 22].try_into().unwrap_or([0; 4]));
        let bi_height =
            i32::from_le_bytes(data[offset + 22..offset + 26].try_into().unwrap_or([0; 4]));
        let bi_size_image =
            u32::from_le_bytes(data[offset + 34..offset + 38].try_into().unwrap_or([0; 4]))
                as usize;

        let remaining = data.len() - offset;
        if file_size > remaining {
            findings.push(
                Finding::new(
                    "logofail",
                    Severity::Critical,
                    "LogoFAIL: BMP file size exceeds firmware volume bounds",
                    &format!(
                        "BMP at offset 0x{:08X} declares file size 0x{:X} but only 0x{:X} bytes remain. \
                         This can trigger a heap buffer overflow in UEFI image parsers (CVE-2023-40238).",
                        offset, file_size, remaining
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "declared_size": file_size,
                    "available_bytes": remaining,
                    "cve": "CVE-2023-40238",
                }))
                .with_recommendation("Re-flash firmware from vendor with LogoFAIL patches applied"),
            );
        }

        if bi_height == i32::MIN || bi_height.checked_abs().is_none() {
            findings.push(
                Finding::new(
                    "logofail",
                    Severity::Critical,
                    "LogoFAIL: BMP height integer overflow",
                    &format!(
                        "BMP at offset 0x{:08X} has biHeight=0x{:08X} which causes integer overflow \
                         when negated. Exploitable for arbitrary code execution during DXE.",
                        offset, bi_height as u32
                    ),
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "bi_height": bi_height,
                    "bi_width": bi_width,
                }))
                .with_recommendation("Remove malicious logo image and re-flash with patched firmware"),
            );
        }

        if bi_size_image > remaining && bi_size_image > 0 {
            findings.push(
                Finding::new(
                    "logofail",
                    Severity::High,
                    "LogoFAIL: BMP biSizeImage exceeds available data",
                    &format!(
                        "BMP at offset 0x{:08X} declares biSizeImage=0x{:X} exceeding available firmware \
                         data (0x{:X}). May trigger out-of-bounds read in image decoder.",
                        offset, bi_size_image, remaining
                    ),
                )
                .with_confidence(0.80)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "bi_size_image": bi_size_image,
                    "available_bytes": remaining,
                })),
            );
        }

        if bi_width > 10000 || bi_height.unsigned_abs() > 10000 {
            findings.push(
                Finding::new(
                    "logofail",
                    Severity::Medium,
                    "LogoFAIL: Suspiciously large BMP dimensions in firmware",
                    &format!(
                        "BMP at offset 0x{:08X} has dimensions {}x{} which is abnormally large for \
                         a boot logo. May be crafted to cause excessive memory allocation.",
                        offset, bi_width, bi_height
                    ),
                )
                .with_confidence(0.60),
            );
        }

        findings
    }

    fn check_png_header(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + 24 > data.len() {
            return findings;
        }

        // IHDR chunk should follow the PNG signature
        let chunk_len =
            u32::from_be_bytes(data[offset + 8..offset + 12].try_into().unwrap_or([0; 4])) as usize;

        if chunk_len > 0x1000000 {
            findings.push(
                Finding::new(
                    "logofail",
                    Severity::High,
                    "LogoFAIL: PNG with oversized IHDR chunk in firmware",
                    &format!(
                        "PNG at offset 0x{:08X} has first chunk length 0x{:X} which is abnormally large. \
                         May exploit PNG parser heap overflow vulnerabilities.",
                        offset, chunk_len
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "chunk_length": chunk_len,
                })),
            );
        }

        findings
    }
}

impl Detector for LogofailDetector {
    fn name(&self) -> &str {
        "logofail"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        let in_firmware_volume = data.windows(4).any(|w| w == EFI_FV_SIGNATURE);

        if !in_firmware_volume {
            return Ok(findings);
        }

        // Scan for BMP images within firmware
        for i in 0..data.len().saturating_sub(54) {
            if data[i..i + 2] == BMP_MAGIC {
                let pixel_offset =
                    u32::from_le_bytes(data[i + 10..i + 14].try_into().unwrap_or([0; 4]));
                if (54..0x10000).contains(&pixel_offset) {
                    findings.extend(self.check_bmp_header(&data, i));
                }
            }
        }

        // Scan for PNG images within firmware
        for i in 0..data.len().saturating_sub(24) {
            if data[i..i + 8] == PNG_MAGIC {
                findings.extend(self.check_png_header(&data, i));
            }
        }

        // Scan for JPEG images - unusual in UEFI firmware
        let jpeg_count = data.windows(2).filter(|w| *w == JPEG_MAGIC).count();
        if jpeg_count > 5 {
            findings.push(
                Finding::new(
                    "logofail",
                    Severity::Medium,
                    "LogoFAIL: Multiple JPEG images embedded in firmware",
                    &format!(
                        "Found {} JPEG signatures in firmware image. JPEG parsers in UEFI are \
                         historically vulnerable. Unusual count may indicate injected payloads.",
                        jpeg_count
                    ),
                )
                .with_confidence(0.55),
            );
        }

        Ok(findings)
    }
}
