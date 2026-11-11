use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_FV_SIGNATURE: &[u8] = b"_FVH";
#[allow(dead_code)]
const EFI_FFS_HEADER_SIZE: usize = 24;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum FfsFileType {
    Raw = 0x01,
    Freeform = 0x02,
    SecurityCore = 0x03,
    PeiCore = 0x04,
    DxeCore = 0x05,
    Peim = 0x06,
    Driver = 0x07,
    Application = 0x09,
    FirmwareVolumeImage = 0x0B,
    Unknown = 0xFF,
}

impl From<u8> for FfsFileType {
    fn from(val: u8) -> Self {
        match val {
            0x01 => Self::Raw,
            0x02 => Self::Freeform,
            0x03 => Self::SecurityCore,
            0x04 => Self::PeiCore,
            0x05 => Self::DxeCore,
            0x06 => Self::Peim,
            0x07 => Self::Driver,
            0x09 => Self::Application,
            0x0B => Self::FirmwareVolumeImage,
            _ => Self::Unknown,
        }
    }
}

pub struct FirmwareVolumeDetector;

impl Default for FirmwareVolumeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FirmwareVolumeDetector {
    pub fn new() -> Self {
        Self
    }

    fn find_firmware_volumes(&self, data: &[u8]) -> Vec<usize> {
        let mut offsets = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            if let Some(offset) = data[pos..].windows(4).position(|w| w == EFI_FV_SIGNATURE) {
                // Subtract from the absolute position, not the window offset.
                if let Some(fv_start) = (pos + offset).checked_sub(40) {
                    offsets.push(fv_start);
                }
                pos = pos + offset + 4;
            } else {
                break;
            }
        }
        offsets
    }

    fn check_fv_integrity(&self, data: &[u8], fv_offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check FV header checksum
        if fv_offset + 56 > data.len() {
            return findings;
        }

        let raw_length = u64::from_le_bytes(
            data[fv_offset + 32..fv_offset + 40]
                .try_into()
                .unwrap_or([0; 8]),
        );
        let Ok(fv_length) = usize::try_from(raw_length) else {
            return findings;
        };

        if fv_length < 56 || fv_length > data.len() - fv_offset {
            return findings;
        }

        // Header checksum (16-bit sum should be 0)
        let header_length = u16::from_le_bytes(
            data[fv_offset + 48..fv_offset + 50]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;

        if header_length >= 56 && header_length <= fv_length && header_length.is_multiple_of(2) {
            let mut sum: u16 = 0;
            for chunk in data[fv_offset..fv_offset + header_length].chunks(2) {
                let word = if chunk.len() == 2 {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    chunk[0] as u16
                };
                sum = sum.wrapping_add(word);
            }

            if sum != 0 {
                findings.push(
                    Finding::new(
                        "firmware_volume",
                        Severity::High,
                        "Firmware Volume header checksum failure",
                        &format!(
                            "FV at offset 0x{:08X} has invalid header checksum (0x{:04X}). \
                             Volume may have been tampered with.",
                            fv_offset, sum
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "fv_offset": format!("0x{:08X}", fv_offset),
                        "fv_length": fv_length,
                        "checksum": format!("0x{:04X}", sum),
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for FirmwareVolumeDetector {
    fn name(&self) -> &str {
        "firmware_volume"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        let fv_offsets = self.find_firmware_volumes(&data);

        if fv_offsets.is_empty() && data.len() > 0x10000 {
            findings.push(Finding::new(
                "firmware_volume",
                Severity::Medium,
                "No firmware volumes found",
                "No EFI Firmware Volume headers found in image. \
                 May indicate the image is corrupted or not a valid UEFI firmware.",
            ));
            return Ok(findings);
        }

        for &offset in &fv_offsets {
            findings.extend(self.check_fv_integrity(&data, offset));
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn minimized_fuzzer_overflow_regression() {
        // Minimized from libFuzzer's 60-byte crash; no sensitive firmware data.
        let mut data = vec![0xff; 60];
        data[..4].copy_from_slice(b"_FVH");
        data[16..20].copy_from_slice(b"_FVH");
        data[49..56].fill(0);
        data[56] = 8;
        let detector = FirmwareVolumeDetector;
        assert!(detector.check_fv_integrity(&data, 4).is_empty());
        assert!(detector.find_firmware_volumes(&data).is_empty());
    }
    #[test]
    fn absolute_header_offsets_and_maximal_lengths_are_bounded() {
        let mut data = vec![0u8; 128];
        data[40..44].copy_from_slice(b"_FVH");
        data[104..108].copy_from_slice(b"_FVH");
        data[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        let detector = FirmwareVolumeDetector;
        assert_eq!(detector.find_firmware_volumes(&data), [0, 64]);
        assert!(detector.check_fv_integrity(&data, 0).is_empty());
    }
}
