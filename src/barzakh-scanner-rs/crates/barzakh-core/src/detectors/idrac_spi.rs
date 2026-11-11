use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const IDRAC_MAGIC: &[u8] = b"iDRAC";
const REDFISH_DELL_OEM: &[u8] = b"/redfish/v1/Managers/iDRAC";
const RACADM_SPI: &[u8] = b"racadm set BIOS.SpiAccess";
const SPI_DESCRIPTOR_MAGIC: [u8; 4] = [0x5A, 0xA5, 0xF0, 0x0F];
const DELL_OEM_NETFN: u8 = 0x30;
const DELL_SPI_WRITE_CMD: u8 = 0xCE;

pub struct IdracSpiDetector;

impl Default for IdracSpiDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IdracSpiDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_idrac_spi_crossdomain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_idrac = data.windows(IDRAC_MAGIC.len()).any(|w| w == IDRAC_MAGIC);

        if !has_idrac {
            return findings;
        }

        let has_spi_descriptor = data
            .windows(SPI_DESCRIPTOR_MAGIC.len())
            .any(|w| w == SPI_DESCRIPTOR_MAGIC);

        if has_spi_descriptor {
            // Check for BMC master access grant with BIOS region write
            for i in 0..data.len().saturating_sub(4) {
                if data[i..i + 4] == SPI_DESCRIPTOR_MAGIC {
                    let region_end = (i + 64).min(data.len());
                    let region = &data[i..region_end];

                    let has_write_enable = region.contains(&0x06);
                    let has_page_program = region.contains(&0x02);

                    if has_write_enable || has_page_program {
                        findings.push(
                            Finding::new(
                                "idrac_spi",
                                Severity::Critical,
                                "iDRAC cross-domain SPI flash write to host BIOS region",
                                &format!(
                                    "iDRAC firmware with SPI flash descriptor at offset 0x{:08X} \
                                     containing write-enable (WREN) or page-program commands. \
                                     Indicates BMC-to-host lateral movement via direct SPI bus access.",
                                    i
                                ),
                            )
                            .with_confidence(0.90)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "has_write_enable": has_write_enable,
                                "has_page_program": has_page_program,
                                "technique": "iDRAC BMC-to-host SPI flash lateral movement",
                            }))
                            .with_recommendation(
                                "Restrict iDRAC SPI master access via FLMSTR3 configuration and enable SPI flash write protection",
                            ),
                        );
                        break;
                    }
                }
            }
        }

        findings
    }

    fn check_dell_oem_ipmi_spi(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // A Dell OEM IPMI write command is only meaningful in BMC-bearing
        // firmware. Without iDRAC/racadm/IPMI context anywhere in the
        // image, a `30 CE` byte pair is coincidence (it occurs regularly
        // in compressed firmware volumes).
        let has_bmc_context = data.windows(5).any(|w| w == IDRAC_MAGIC)
            || data
                .windows(RACADM_SPI.len())
                .any(|w| w == &RACADM_SPI[..8])
            || data.windows(4).any(|w| w == b"IPMI");
        if !has_bmc_context {
            return findings;
        }

        for i in 0..data.len().saturating_sub(8) {
            if data[i] == DELL_OEM_NETFN && data[i + 1] == DELL_SPI_WRITE_CMD {
                let cmd_end = (i + 16).min(data.len());
                let cmd_region = &data[i..cmd_end];

                let targets_bios_region = cmd_region.contains(&0x01);

                if targets_bios_region {
                    findings.push(
                        Finding::new(
                            "idrac_spi",
                            Severity::Critical,
                            "Dell OEM IPMI command for SPI flash write targeting BIOS region",
                            &format!(
                                "Dell OEM IPMI command (NetFn=0x30, Cmd=0xCE) at offset 0x{:08X} \
                                 targeting BIOS flash region. This is the iDRAC-specific command \
                                 for cross-domain SPI write from BMC to host.",
                                i
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "netfn": "0x30 (Dell OEM)",
                            "command": "0xCE (SPI flash write)",
                            "target_region": "BIOS (0x01)",
                            "technique": "Dell iDRAC OEM IPMI SPI write command",
                        }))
                        .with_recommendation(
                            "Disable iDRAC SPI flash write capability and audit BMC firmware integrity",
                        ),
                    );
                    break;
                }
            }
        }

        findings
    }

    fn check_redfish_bios_update(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(REDFISH_DELL_OEM.len())
            .position(|w| w == REDFISH_DELL_OEM)
        {
            let region_end = (pos + 512).min(data.len());
            let region = &data[pos..region_end];

            let has_spi_access = region.windows(9).any(|w| w == b"SpiAccess");

            if has_spi_access {
                findings.push(
                    Finding::new(
                        "idrac_spi",
                        Severity::High,
                        "iDRAC Redfish endpoint with SPI access configuration",
                        &format!(
                            "iDRAC Redfish management endpoint at offset 0x{:08X} with SPI \
                             access attribute reference. Indicates potential for remote SPI \
                             flash modification through iDRAC management interface.",
                            pos
                        ),
                    )
                    .with_confidence(0.78)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "endpoint": "iDRAC Redfish Manager",
                        "has_spi_access_attr": true,
                        "technique": "Redfish-based iDRAC SPI access",
                    }))
                    .with_recommendation(
                        "Restrict iDRAC Redfish access and disable remote BIOS update capabilities",
                    ),
                );
            }
        }

        findings
    }

    fn check_racadm_spi_command(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data.windows(RACADM_SPI.len()).position(|w| w == RACADM_SPI) {
            findings.push(
                Finding::new(
                    "idrac_spi",
                    Severity::High,
                    "RACADM command enabling SPI flash access from iDRAC",
                    &format!(
                        "Found RACADM SPI access command at offset 0x{:08X}. This command \
                         enables direct SPI flash bus access from the iDRAC BMC, allowing \
                         host BIOS modification without host-side authentication.",
                        pos
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", pos),
                    "command": "racadm set BIOS.SpiAccess",
                    "technique": "RACADM-based SPI access enablement",
                }))
                .with_recommendation(
                    "Disable RACADM SPI access commands and enforce separation between BMC and host flash",
                ),
            );
        }

        findings
    }
}

impl Detector for IdracSpiDetector {
    fn name(&self) -> &str {
        "idrac_spi"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_idrac_spi_crossdomain(&data));
        findings.extend(self.check_dell_oem_ipmi_spi(&data));
        findings.extend(self.check_redfish_bios_update(&data));
        findings.extend(self.check_racadm_spi_command(&data));

        Ok(findings)
    }
}
