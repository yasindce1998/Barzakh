use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const DELL_BIOS_CONNECT_MARKER: &[u8] = b"DellBIOSConnect";
const SUPPORT_ASSIST_MARKER: &[u8] = b"SupportAssist";
const DELL_CERT_CN: &[u8] = b"CN=Dell Inc Root CA";
const DELL_RECOVERY_CN: &[u8] = b"CN=Dell Recovery Services";
const TLS_CIPHER_MARKER: &[u8] = b"TLS_RSA_WITH_AES_256_CBC_SHA";

pub struct DellBiosConnectDetector;

impl Default for DellBiosConnectDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DellBiosConnectDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_bios_connect_dxe(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(DELL_BIOS_CONNECT_MARKER.len())
            .position(|w| w == DELL_BIOS_CONNECT_MARKER)
        {
            let search_end = (pos + 2048).min(data.len());
            let region = &data[pos..search_end];

            let has_tls = region
                .windows(TLS_CIPHER_MARKER.len())
                .any(|w| w == TLS_CIPHER_MARKER);

            if has_tls {
                findings.push(
                    Finding::new(
                        "dell_bios_connect",
                        Severity::High,
                        "Dell BIOSConnect DXE with network TLS stack",
                        &format!(
                            "Found Dell BIOSConnect driver marker at offset 0x{:08X} with TLS \
                             cipher suite references. This DXE module performs network-based BIOS \
                             recovery and may be vulnerable to MITM attacks (CVE-2021-21571).",
                            pos
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "has_tls_stack": true,
                        "cve": "CVE-2021-21571",
                        "technique": "Dell BIOSConnect network recovery MITM",
                    }))
                    .with_recommendation(
                        "Disable BIOSConnect in Dell BIOS settings and update to patched firmware",
                    ),
                );
            }
        }

        findings
    }

    fn check_spoofed_cert_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_dell_root = data.windows(DELL_CERT_CN.len()).any(|w| w == DELL_CERT_CN);

        let has_dell_intermediate = data
            .windows(DELL_RECOVERY_CN.len())
            .any(|w| w == DELL_RECOVERY_CN);

        if has_dell_root && has_dell_intermediate {
            // Check for X.509 ASN.1 structure (SEQUENCE tag 0x30 0x82)
            let has_asn1_cert = data.windows(4).any(|w| w[0] == 0x30 && w[1] == 0x82);

            if has_asn1_cert {
                findings.push(
                    Finding::new(
                        "dell_bios_connect",
                        Severity::Critical,
                        "Spoofed Dell certificate chain for BIOSConnect MITM",
                        "Found embedded X.509 certificate chain with Dell Root CA and Dell \
                         Recovery Services subjects. This indicates a crafted certificate chain \
                         that could intercept Dell BIOSConnect BIOS recovery traffic.",
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "has_root_cert": true,
                        "has_intermediate_cert": true,
                        "has_asn1_structure": true,
                        "technique": "Certificate chain spoofing for BIOS recovery MITM",
                    }))
                    .with_recommendation(
                        "Verify certificate chain against Dell's actual root CA and reject untrusted certs",
                    ),
                );
            }
        }

        findings
    }

    fn check_support_assist_version(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(SUPPORT_ASSIST_MARKER.len())
            .position(|w| w == SUPPORT_ASSIST_MARKER)
        {
            let version_region_end = (pos + 64).min(data.len());
            let version_region = &data[pos..version_region_end];

            let has_vuln_version = version_region
                .windows(4)
                .any(|w| w == b"3.11" || w == b"3.10" || w == b"3.9." || w == b"3.8.");

            if has_vuln_version {
                findings.push(
                    Finding::new(
                        "dell_bios_connect",
                        Severity::High,
                        "Vulnerable Dell SupportAssist version detected",
                        &format!(
                            "Dell SupportAssist reference at offset 0x{:08X} with version in \
                             known-vulnerable range (< 3.12). Versions prior to 3.12 are \
                             susceptible to BIOSConnect TLS verification bypass.",
                            pos
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "technique": "Dell SupportAssist vulnerable version",
                    }))
                    .with_recommendation("Update Dell SupportAssist to version 3.12 or later"),
                );
            }
        }

        findings
    }
}

impl Detector for DellBiosConnectDetector {
    fn name(&self) -> &str {
        "dell_bios_connect"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_bios_connect_dxe(&data));
        findings.extend(self.check_spoofed_cert_chain(&data));
        findings.extend(self.check_support_assist_version(&data));

        Ok(findings)
    }
}
