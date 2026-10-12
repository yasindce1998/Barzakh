use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EZ_FLASH_UPDATE_URL: &[u8] = b"EzFlashUpdateUrl";
const EZ_FLASH_SKIP_VERIFY: &[u8] = b"EzFlashSkipVerify";
const ASUS_VAR_GUID: [u8; 16] = [
    0x72, 0x3B, 0xE2, 0xA5, 0x5A, 0x3B, 0x4E, 0x4C, 0x8C, 0x2B, 0x4F, 0x89, 0xDE, 0xFA, 0x12, 0x34,
];

pub struct AsusNvramDetector;

impl Default for AsusNvramDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AsusNvramDetector {
    pub fn new() -> Self {
        Self
    }

    /// Extract the hostname of the first http(s):// URL in `region` and
    /// check it is not an ASUS-owned domain. Substring-scanning the whole
    /// region is wrong: a URL like http://evil-fw-server.net/asus/bios.cap
    /// contains "asus" in the *path* and would slip past the check.
    fn url_host_is_non_asus(region: &[u8]) -> bool {
        let url_start = match region
            .windows(7)
            .position(|w| w == b"http://")
            .or_else(|| region.windows(8).position(|w| w == b"https://"))
        {
            Some(p) => p,
            None => return false,
        };

        let after_scheme = url_start
            + if region[url_start..].starts_with(b"https://") {
                8
            } else {
                7
            };

        // Host runs to the first '/', '?', or end of region.
        let host_end = region[after_scheme..]
            .iter()
            .position(|&b| b == b'/' || b == b'?')
            .map(|i| after_scheme + i)
            .unwrap_or(region.len());
        let host = &region[after_scheme..host_end];

        if host.is_empty() {
            return false;
        }

        // ASUS-owned domains (asus.com and regional variants like
        // asus.com.tw, dlcdnnts.asus.com). Compare case-insensitively
        // against the registrable domain: the label immediately before
        // the TLD ("dlcdnnts.asus.com" -> "asus", "evil-fw-server.net"
        // -> "evil-fw-server"), or the whole host if it has no dot.
        let host_lower = host.to_ascii_lowercase();
        let last_dot = host_lower.iter().rposition(|&b| b == b'.');
        let registrable: &[u8] = match last_dot {
            Some(tld_dot) => {
                let before_tld = &host_lower[..tld_dot];
                match before_tld.iter().rposition(|&b| b == b'.') {
                    Some(dot) => &before_tld[dot + 1..],
                    // "asus.com" -> "asus"; single label + TLD
                    None => before_tld,
                }
            }
            // Dotless host — treat the whole thing as the domain
            None => &host_lower,
        };
        registrable != b"asus"
    }

    fn check_nvram_url_redirect(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(EZ_FLASH_UPDATE_URL.len())
            .position(|w| w == EZ_FLASH_UPDATE_URL)
        {
            let search_start = pos;
            let search_end = (pos + 512).min(data.len());
            let region = &data[search_start..search_end];

            if Self::url_host_is_non_asus(region) {
                findings.push(
                    Finding::new(
                        "asus_nvram",
                        Severity::Critical,
                        "ASUS EZ Flash NVRAM update URL redirected to non-ASUS HTTP endpoint",
                        &format!(
                            "Found EzFlashUpdateUrl NVRAM variable at offset 0x{:08X} containing \
                             an HTTP (non-HTTPS) URL pointing to a non-ASUS domain. Indicates NVRAM \
                             tampering to redirect firmware updates to an attacker-controlled server.",
                            pos
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "non_asus_host": true,
                        "technique": "NVRAM variable tampering for firmware update redirection",
                    }))
                    .with_recommendation(
                        "Clear NVRAM variables and reflash ASUS BIOS from verified source",
                    ),
                );
            }
        }

        findings
    }

    fn check_signature_bypass(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(pos) = data
            .windows(EZ_FLASH_SKIP_VERIFY.len())
            .position(|w| w == EZ_FLASH_SKIP_VERIFY)
        {
            let value_offset = (pos + EZ_FLASH_SKIP_VERIFY.len() + 0x30).min(data.len() - 1);
            let skip_enabled = data[value_offset] == 0x01;

            if skip_enabled {
                findings.push(
                    Finding::new(
                        "asus_nvram",
                        Severity::Critical,
                        "ASUS EZ Flash signature verification bypass enabled via NVRAM",
                        &format!(
                            "Found EzFlashSkipVerify NVRAM variable at offset 0x{:08X} set to \
                             enabled (0x01). This disables capsule signature verification, \
                             allowing unsigned firmware to be flashed.",
                            pos
                        ),
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "skip_verify_enabled": true,
                        "technique": "NVRAM variable manipulation to bypass signature checks",
                    }))
                    .with_recommendation(
                        "Reset NVRAM to factory defaults and enable Secure Flash verification",
                    ),
                );
            }
        }

        findings
    }

    fn check_asus_var_guid_presence(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(guid_pos) = data
            .windows(ASUS_VAR_GUID.len())
            .position(|w| w == ASUS_VAR_GUID)
        {
            let region_end = (guid_pos + 256).min(data.len());
            let region = &data[guid_pos..region_end];

            let has_url_var = region
                .windows(EZ_FLASH_UPDATE_URL.len())
                .any(|w| w == EZ_FLASH_UPDATE_URL);
            let has_skip_var = region
                .windows(EZ_FLASH_SKIP_VERIFY.len())
                .any(|w| w == EZ_FLASH_SKIP_VERIFY);

            if has_url_var || has_skip_var {
                findings.push(
                    Finding::new(
                        "asus_nvram",
                        Severity::High,
                        "ASUS vendor NVRAM variable space contains update control variables",
                        &format!(
                            "ASUS update control GUID at offset 0x{:08X} with {} present. \
                             These variables control firmware update behavior and may be \
                             tampered to facilitate malicious updates.",
                            guid_pos,
                            if has_url_var && has_skip_var {
                                "URL redirect and skip-verify variables"
                            } else if has_url_var {
                                "URL redirect variable"
                            } else {
                                "skip-verify variable"
                            }
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "guid_offset": format!("0x{:08X}", guid_pos),
                        "has_url_variable": has_url_var,
                        "has_skip_verify_variable": has_skip_var,
                        "technique": "ASUS NVRAM variable space manipulation",
                    }))
                    .with_recommendation(
                        "Audit ASUS NVRAM variable store for unauthorized modifications",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for AsusNvramDetector {
    fn name(&self) -> &str {
        "asus_nvram"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_nvram_url_redirect(&data));
        findings.extend(self.check_signature_bypass(&data));
        findings.extend(self.check_asus_var_guid_presence(&data));

        Ok(findings)
    }
}
