use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const HTTP_RESPONSE_OK: &[u8] = b"HTTP/1.1 200";
const CONTENT_TYPE_EFI: &[u8] = b"application/efi";
const PE_MAGIC: &[u8] = b"MZ";
const HTTP_BOOT_VAR: &[u8] = b"H\x00T\x00T\x00P\x00B\x00o\x00o\x00t\x00";
const CERT_BYPASS_MARKER: &[u8] = b"TlsVerify=FALSE";

pub struct HttpBootDetector;

impl Default for HttpBootDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpBootDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_http_pe_payload(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(http_pos) = data
            .windows(HTTP_RESPONSE_OK.len())
            .position(|w| w == HTTP_RESPONSE_OK)
        {
            let header_end = (http_pos + 2048).min(data.len());
            let header_region = &data[http_pos..header_end];

            let has_efi_content = header_region
                .windows(CONTENT_TYPE_EFI.len())
                .any(|w| w == CONTENT_TYPE_EFI);

            if has_efi_content {
                let body_marker = b"\r\n\r\n";
                if let Some(body_pos) = header_region
                    .windows(body_marker.len())
                    .position(|w| w == body_marker)
                {
                    let pe_start = http_pos + body_pos + body_marker.len();
                    if pe_start + 2 < data.len() && data[pe_start..pe_start + 2] == *PE_MAGIC {
                        findings.push(
                            Finding::new(
                                "http_boot",
                                Severity::High,
                                "HTTP Boot response with embedded PE/EFI payload",
                                &format!(
                                    "Found HTTP 200 response at offset 0x{:08X} with \
                                     Content-Type: application/efi and embedded PE image at \
                                     0x{:08X}. This matches UEFI HTTP Boot MITM injection \
                                     where an attacker serves malicious EFI binaries.",
                                    http_pos, pe_start
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "http_offset": format!("0x{:08X}", http_pos),
                                "pe_offset": format!("0x{:08X}", pe_start),
                                "content_type": "application/efi",
                                "technique": "UEFI HTTP Boot MITM",
                            }))
                            .with_recommendation(
                                "Enable HTTPS Boot with certificate pinning and disable plain HTTP boot",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }

    fn check_cert_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let has_http_boot_var = data
            .windows(HTTP_BOOT_VAR.len())
            .any(|w| w == HTTP_BOOT_VAR);
        let has_cert_bypass = data
            .windows(CERT_BYPASS_MARKER.len())
            .any(|w| w == CERT_BYPASS_MARKER);

        if has_http_boot_var && has_cert_bypass {
            findings.push(
                Finding::new(
                    "http_boot",
                    Severity::High,
                    "HTTP Boot with TLS verification disabled",
                    "Found HTTPBoot UEFI variable alongside TlsVerify=FALSE marker. \
                     Disabling TLS verification in HTTP Boot context allows MITM attacks \
                     to serve unsigned firmware payloads.",
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "http_boot_var": true,
                    "tls_verify_disabled": true,
                    "technique": "HTTP Boot certificate pinning bypass",
                }))
                .with_recommendation(
                    "Re-enable TLS verification and configure proper CA certificates for HTTP Boot",
                ),
            );
        }

        findings
    }
}

impl Detector for HttpBootDetector {
    fn name(&self) -> &str {
        "http_boot"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_http_pe_payload(&data));
        findings.extend(self.check_cert_bypass(&data));

        Ok(findings)
    }
}
