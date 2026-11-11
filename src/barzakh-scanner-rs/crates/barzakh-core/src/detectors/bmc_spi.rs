use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const IPMI_KCS_NETFN_APP: u8 = 0x06;
const IPMI_OEM_CMD: u8 = 0xC0;
const REDFISH_UPDATE_PATH: &[u8] = b"/redfish/v1/UpdateService";
const SPI_DESCRIPTOR_MAGIC: &[u8] = &[0x5A, 0xA5, 0xF0, 0x0F];
const BMC_SPI_MASTER_GRANT: &[u8] = &[0x42, 0x4D, 0x43, 0x5F, 0x53, 0x50, 0x49];

pub struct BmcSpiDetector;

impl Default for BmcSpiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl BmcSpiDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_ipmi_spi_commands(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(8) {
            if data[i] == IPMI_KCS_NETFN_APP && data[i + 1] == IPMI_OEM_CMD {
                let cmd_region_end = (i + 32).min(data.len());
                let cmd_region = &data[i..cmd_region_end];

                let has_spi_target = cmd_region
                    .windows(SPI_DESCRIPTOR_MAGIC.len())
                    .any(|w| w == SPI_DESCRIPTOR_MAGIC);

                if has_spi_target {
                    findings.push(
                        Finding::new(
                            "bmc_spi",
                            Severity::Critical,
                            "BMC IPMI command targeting host SPI flash descriptor",
                            &format!(
                                "Found IPMI KCS command (NetFn=0x06, OEM Cmd=0xC0) at offset \
                                 0x{:08X} with SPI flash descriptor magic in payload. Indicates \
                                 BMC-to-host lateral movement via SPI flash write.",
                                i
                            ),
                        )
                        .with_confidence(0.88)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "netfn": format!("0x{:02X}", IPMI_KCS_NETFN_APP),
                            "command": format!("0x{:02X}", IPMI_OEM_CMD),
                            "technique": "BMC lateral movement to host SPI",
                        }))
                        .with_recommendation(
                            "Audit BMC firmware integrity and restrict SPI flash write access from BMC",
                        ),
                    );
                }
            }
        }

        findings
    }

    fn check_redfish_spi_update(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(redfish_pos) = data
            .windows(REDFISH_UPDATE_PATH.len())
            .position(|w| w == REDFISH_UPDATE_PATH)
        {
            let search_start = redfish_pos;
            let search_end = (redfish_pos + 512).min(data.len());
            let search_region = &data[search_start..search_end];

            let has_spi_descriptor = search_region
                .windows(SPI_DESCRIPTOR_MAGIC.len())
                .any(|w| w == SPI_DESCRIPTOR_MAGIC);

            let has_bmc_master = search_region
                .windows(BMC_SPI_MASTER_GRANT.len())
                .any(|w| w == BMC_SPI_MASTER_GRANT);

            if has_spi_descriptor || has_bmc_master {
                findings.push(
                    Finding::new(
                        "bmc_spi",
                        Severity::Critical,
                        "Redfish UpdateService with host SPI flash targeting",
                        &format!(
                            "Found Redfish firmware update path at offset 0x{:08X} with {} {}. \
                             Indicates abuse of BMC management interface to write to host SPI flash.",
                            redfish_pos,
                            if has_spi_descriptor {
                                "SPI descriptor magic"
                            } else {
                                ""
                            },
                            if has_bmc_master {
                                "BMC master grant pattern"
                            } else {
                                ""
                            },
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", redfish_pos),
                        "has_spi_descriptor": has_spi_descriptor,
                        "has_bmc_master_grant": has_bmc_master,
                        "technique": "Redfish-based BMC-to-host SPI write",
                    }))
                    .with_recommendation(
                        "Restrict Redfish UpdateService access and enable SPI flash write protection",
                    ),
                );
            }
        }

        findings
    }

    fn check_bmc_master_grant(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(grant_pos) = data
            .windows(BMC_SPI_MASTER_GRANT.len())
            .position(|w| w == BMC_SPI_MASTER_GRANT)
        {
            let region_end = (grant_pos + 64).min(data.len());
            let region = &data[grant_pos..region_end];

            let has_write_enable = region.contains(&0x06);
            let has_sector_erase = region.iter().any(|&b| b == 0x20 || b == 0xD8);

            if has_write_enable && has_sector_erase {
                findings.push(
                    Finding::new(
                        "bmc_spi",
                        Severity::High,
                        "BMC SPI master grant with flash write/erase commands",
                        &format!(
                            "BMC_SPI master grant at offset 0x{:08X} is followed by SPI write \
                             enable (0x06) and sector erase commands. Indicates active SPI flash \
                             modification attempt from BMC.",
                            grant_pos
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", grant_pos),
                        "write_enable": has_write_enable,
                        "sector_erase": has_sector_erase,
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for BmcSpiDetector {
    fn name(&self) -> &str {
        "bmc_spi"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_ipmi_spi_commands(&data));
        findings.extend(self.check_redfish_spi_update(&data));
        findings.extend(self.check_bmc_master_grant(&data));

        Ok(findings)
    }
}
