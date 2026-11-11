use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PCIE_EXT_CAP_CXL: u16 = 0x0023;
const CXL_DVSEC_VENDOR_ID: u16 = 0x1E98;

pub struct CxlDeviceDetector;

impl Default for CxlDeviceDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl CxlDeviceDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_cxl_dvsec(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();

        if offset + 16 > data.len() {
            return findings;
        }

        // PCIe Extended Capability Header (4 bytes):
        // [0:2] = Capability ID
        // [2:4] = Version(4) + Next(12)
        // DVSEC Header:
        // [4:6] = DVSEC Vendor ID
        // [6:8] = DVSEC Revision + Length
        // [8:10] = DVSEC ID

        let cap_id = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap_or([0; 2]));

        if cap_id != PCIE_EXT_CAP_CXL {
            return findings;
        }

        let dvsec_vendor =
            u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap_or([0; 2]));
        let dvsec_len =
            u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap_or([0; 2])) & 0x0FFF;
        let dvsec_id =
            u16::from_le_bytes(data[offset + 8..offset + 10].try_into().unwrap_or([0; 2]));

        // Check for CXL device with DMA capabilities
        if offset + 32 < data.len() {
            self.check_memory_ranges(data, offset, dvsec_id, &mut findings);
        }

        // Check for suspicious DVSEC length (too large)
        if dvsec_len as usize > data.len().saturating_sub(offset) {
            findings.push(
                Finding::new(
                    "cxl_device",
                    Severity::High,
                    "CXL Device: DVSEC length exceeds config space bounds",
                    &format!(
                        "CXL DVSEC at offset 0x{:08X} declares length {} but only {} bytes \
                         remain. Oversized DVSEC may trigger parser overflow in firmware.",
                        offset,
                        dvsec_len,
                        data.len() - offset
                    ),
                )
                .with_confidence(0.82)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "dvsec_vendor": format!("0x{:04X}", dvsec_vendor),
                    "dvsec_id": format!("0x{:04X}", dvsec_id),
                    "declared_length": dvsec_len,
                    "available": data.len() - offset,
                }))
                .with_recommendation(
                    "Verify CXL device firmware and check for config space corruption",
                ),
            );
        }

        // Unknown vendor in CXL DVSEC — potential rogue device
        if dvsec_vendor != CXL_DVSEC_VENDOR_ID && dvsec_vendor != 0x8086 && dvsec_vendor != 0 {
            findings.push(
                Finding::new(
                    "cxl_device",
                    Severity::Medium,
                    "CXL Device: Non-standard vendor ID in DVSEC",
                    &format!(
                        "CXL DVSEC at offset 0x{:08X} has vendor ID 0x{:04X} which is not a \
                         recognized CXL consortium member. May indicate a rogue CXL device.",
                        offset, dvsec_vendor
                    ),
                )
                .with_confidence(0.55)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "dvsec_vendor": format!("0x{:04X}", dvsec_vendor),
                    "dvsec_id": format!("0x{:04X}", dvsec_id),
                })),
            );
        }

        findings
    }

    fn check_memory_ranges(
        &self,
        data: &[u8],
        dvsec_offset: usize,
        dvsec_id: u16,
        findings: &mut Vec<Finding>,
    ) {
        // CXL.mem DVSEC (ID 0x0) contains HDM (Host-managed Device Memory) decoder ranges
        // Check if any DMA ranges overlap with system memory regions
        if dvsec_id != 0x0000 && dvsec_id != 0x0008 {
            return;
        }

        // Look for BAR/memory range registers after DVSEC header
        let range_offset = dvsec_offset + 16;
        if range_offset + 16 > data.len() {
            return;
        }

        let base_low = u32::from_le_bytes(
            data[range_offset..range_offset + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let base_high = u32::from_le_bytes(
            data[range_offset + 4..range_offset + 8]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let size_low = u32::from_le_bytes(
            data[range_offset + 8..range_offset + 12]
                .try_into()
                .unwrap_or([0; 4]),
        );

        let base_addr = ((base_high as u64) << 32) | base_low as u64;
        let range_size = size_low as u64;

        // Check for DMA ranges in low memory (below 4GB) where system structures live
        if base_addr < 0x100000000 && base_addr > 0 && range_size > 0 {
            // Ranges below 1MB overlap with legacy BIOS/SMM area
            if base_addr < 0x100000 {
                findings.push(
                    Finding::new(
                        "cxl_device",
                        Severity::Critical,
                        "CXL Device: DMA range overlaps system memory (SMM/legacy area)",
                        &format!(
                            "CXL device DVSEC at offset 0x{:08X} maps memory at base 0x{:08X} \
                             (size 0x{:X}) which overlaps the first 1MB of system memory. \
                             This enables DMA attacks against SMM and interrupt vectors.",
                            dvsec_offset, base_addr, range_size
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "dvsec_offset": format!("0x{:08X}", dvsec_offset),
                        "base_address": format!("0x{:016X}", base_addr),
                        "range_size": format!("0x{:X}", range_size),
                        "dvsec_id": format!("0x{:04X}", dvsec_id),
                    }))
                    .with_recommendation(
                        "Enable IOMMU/VT-d protection for CXL devices and restrict DMA ranges",
                    ),
                );
            }
            // Check for overlap with typical UEFI runtime services area
            else if (0x70000000..0x80000000).contains(&base_addr) {
                findings.push(
                    Finding::new(
                        "cxl_device",
                        Severity::High,
                        "CXL Device: DMA range overlaps UEFI runtime memory region",
                        &format!(
                            "CXL device at offset 0x{:08X} maps DMA at 0x{:08X} (size 0x{:X}) \
                             which may overlap UEFI runtime services memory. Could enable \
                             runtime code modification via CXL.mem.",
                            dvsec_offset, base_addr, range_size
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "dvsec_offset": format!("0x{:08X}", dvsec_offset),
                        "base_address": format!("0x{:016X}", base_addr),
                        "range_size": format!("0x{:X}", range_size),
                    })),
                );
            }
        }
    }

    fn check_pcie_config_anomalies(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for PCIe config space dumps with suspicious capability chains
        // Extended capabilities start at offset 0x100 in PCIe config space
        let mut cap_offset = 0x100usize;
        let mut visited = 0;

        while cap_offset > 0 && cap_offset + 4 < data.len() && visited < 50 {
            let cap_id = u16::from_le_bytes(
                data[cap_offset..cap_offset + 2]
                    .try_into()
                    .unwrap_or([0; 2]),
            );
            let next_and_version = u16::from_le_bytes(
                data[cap_offset + 2..cap_offset + 4]
                    .try_into()
                    .unwrap_or([0; 2]),
            );
            let next_cap = (next_and_version >> 4) as usize;

            if cap_id == PCIE_EXT_CAP_CXL {
                findings.extend(self.check_cxl_dvsec(data, cap_offset));
            }

            if next_cap == 0 || next_cap <= cap_offset {
                break;
            }
            cap_offset = next_cap;
            visited += 1;
        }

        if visited >= 50 {
            findings.push(
                Finding::new(
                    "cxl_device",
                    Severity::High,
                    "CXL/PCIe: Extended capability chain loop detected",
                    "PCIe extended capability linked list contains a cycle (>50 entries). \
                     Malicious device may use this to cause infinite loop in firmware enumeration.",
                )
                .with_confidence(0.80),
            );
        }

        findings
    }
}

impl Detector for CxlDeviceDetector {
    fn name(&self) -> &str {
        "cxl_device"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Scan for CXL DVSEC structures anywhere in the image
        for i in 0..data.len().saturating_sub(16) {
            let cap_id = u16::from_le_bytes(data[i..i + 2].try_into().unwrap_or([0; 2]));
            if cap_id == PCIE_EXT_CAP_CXL {
                // Verify it looks like a real capability header (version field is reasonable)
                let version = (data.get(i + 2).copied().unwrap_or(0)) & 0x0F;
                if (1..=3).contains(&version) {
                    findings.extend(self.check_cxl_dvsec(&data, i));
                }
            }
        }

        // Also check as PCIe config space dump
        if data.len() >= 0x1000 {
            findings.extend(self.check_pcie_config_anomalies(&data));
        }

        Ok(findings)
    }
}
