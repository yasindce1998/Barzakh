use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const DHCPV6_SOLICIT: u8 = 1;
const DHCPV6_ADVERTISE: u8 = 2;
const DHCPV6_REPLY: u8 = 7;
const OPTION_DNS_SERVERS: u16 = 23;
const OPTION_DOMAIN_LIST: u16 = 24;
const OPTION_BOOTFILE_URL: u16 = 59;

/// DHCPv6 messages are link-layer packets (Ethernet MTU + headers); a
/// multi-megabyte firmware image is never a single DHCPv6 packet. The
/// option walk is bounded to this window so that option lengths are
/// validated against a plausible packet, not the whole image.
const DHCPV6_PACKET_WINDOW: usize = 1500;

/// Bound on reported PixieFail findings per image.
const MAX_PIXIEFAIL_FINDINGS: usize = 16;

/// DHCPv6 option codes defined by RFC 8415. A candidate offset only
/// qualifies as a real DHCPv6 message when its option walk carries at
/// least [`MIN_RECOGNIZED_OPTIONS`] of these codes with in-window
/// lengths — random firmware bytes never do.
const KNOWN_DHCPV6_OPTIONS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 31, 32, 33, 39,
    59, 61, 62, 82,
];
const MIN_RECOGNIZED_OPTIONS: usize = 3;

pub struct PixiefailDetector;

impl Default for PixiefailDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PixiefailDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_dhcpv6_options(&self, data: &[u8], base_offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut pos = 0;

        // A DHCPv6 message is a link-layer packet, never megabytes: bound
        // the option walk to a plausible packet window.
        let window = data.len().min(DHCPV6_PACKET_WINDOW);

        // Qualification pass: walk the options and count recognized
        // RFC 8415 option codes with in-window lengths. Only a candidate
        // carrying several real option codes is a DHCPv6 packet worth
        // reporting on; random firmware bytes interpreted as packets
        // almost never contain even one.
        let mut recognized = 0;
        // A real DHCPv6 message starts with a standard option; random
        // candidates almost never do.
        let mut first_option_recognized = false;
        // At least one recognized option must carry real data (length
        // >= 8, e.g. an IA_NA or a DUID). Repeated tiny options (code 1,
        // length 1 strides in u16 tables) are not packet structure.
        let mut has_substantial_option = false;
        // Real packets reference several *different* options (client id,
        // IA_NA, DNS, ...). Byte runs that qualify via a single option
        // code repeated many times (e.g. `00 10 00 10` table strides)
        // are not packets.
        let mut distinct_codes = std::collections::HashSet::with_capacity(8);
        while pos + 4 <= window {
            let code = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap_or([0; 2]));
            let len =
                u16::from_be_bytes(data[pos + 2..pos + 4].try_into().unwrap_or([0; 2])) as usize;
            if len > window.saturating_sub(pos + 4) {
                break;
            }
            if KNOWN_DHCPV6_OPTIONS.contains(&code) && len > 0 {
                // Zero-length "options" are runs of repeated or zero bytes
                // (e.g. `00 10 00 00` strides), not packet structure; only
                // options carrying data qualify a candidate.
                recognized += 1;
                distinct_codes.insert(code);
                if pos == 0 {
                    first_option_recognized = true;
                }
                if len >= 8 {
                    has_substantial_option = true;
                }
            }
            pos += 4 + len;
        }
        if recognized < MIN_RECOGNIZED_OPTIONS
            || !first_option_recognized
            || !has_substantial_option
            || distinct_codes.len() < 3
        {
            return findings;
        }

        // Reporting pass: the candidate is a plausible DHCPv6 packet.
        pos = 0;
        while pos + 4 <= window {
            let option_code = u16::from_be_bytes(data[pos..pos + 2].try_into().unwrap_or([0; 2]));
            let option_len =
                u16::from_be_bytes(data[pos + 2..pos + 4].try_into().unwrap_or([0; 2])) as usize;

            if option_len > window.saturating_sub(pos + 4) {
                findings.push(
                    Finding::new(
                        "pixiefail",
                        Severity::Critical,
                        "PixieFail: DHCPv6 option length exceeds packet bounds",
                        &format!(
                            "DHCPv6 option {} at offset 0x{:08X} declares length {} but only {} bytes \
                             remain. This triggers CVE-2023-45229 (buffer overflow in EDK2 NetworkPkg).",
                            option_code, base_offset + pos, option_len,
                            window.saturating_sub(pos + 4)
                        ),
                    )
                    .with_confidence(0.92)
                    .with_details(serde_json::json!({
                        "option_code": option_code,
                        "declared_length": option_len,
                        "offset": format!("0x{:08X}", base_offset + pos),
                        "cve": "CVE-2023-45229",
                    }))
                    .with_recommendation("Update EDK2/UEFI firmware to version with PixieFail patches"),
                );
                break;
            }

            if option_code == OPTION_DNS_SERVERS && !option_len.is_multiple_of(16) {
                findings.push(
                    Finding::new(
                        "pixiefail",
                        Severity::High,
                        "PixieFail: Malformed DNS server option (CVE-2023-45231)",
                        &format!(
                            "DHCPv6 DNS Servers option at offset 0x{:08X} has length {} (not \
                             multiple of 16). Can trigger out-of-bounds read in IPv6 address parsing.",
                            base_offset + pos, option_len
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", base_offset + pos),
                        "option_len": option_len,
                        "cve": "CVE-2023-45231",
                    })),
                );
            }

            if option_code == OPTION_DOMAIN_LIST && option_len > 0 && pos + 4 < data.len() {
                let domain_data = &data[pos + 4..pos + 4 + option_len.min(data.len() - pos - 4)];
                if self.has_dns_compression_loop(domain_data) {
                    findings.push(
                        Finding::new(
                            "pixiefail",
                            Severity::Critical,
                            "PixieFail: DNS label compression creates infinite loop (CVE-2023-45232)",
                            &format!(
                                "DHCPv6 Domain List at offset 0x{:08X} contains DNS compression \
                                 pointers creating a cycle. Causes infinite loop in EDK2 DNS parser.",
                                base_offset + pos
                            ),
                        )
                        .with_confidence(0.90)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", base_offset + pos),
                            "cve": "CVE-2023-45232",
                        }))
                        .with_recommendation("Patch EDK2 NetworkPkg to validate DNS compression pointers"),
                    );
                }
            }

            if option_code == OPTION_BOOTFILE_URL && option_len > 512 {
                findings.push(
                    Finding::new(
                        "pixiefail",
                        Severity::High,
                        "PixieFail: Oversized Boot File URL option (CVE-2023-45235)",
                        &format!(
                            "DHCPv6 Boot File URL at offset 0x{:08X} has length {} which can \
                             overflow stack buffers in PXE boot handler.",
                            base_offset + pos,
                            option_len
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", base_offset + pos),
                        "option_len": option_len,
                        "cve": "CVE-2023-45235",
                    })),
                );
            }

            pos += 4 + option_len;
        }

        findings
    }

    fn has_dns_compression_loop(&self, data: &[u8]) -> bool {
        let mut pos = 0;
        let mut jumps = 0;
        while pos < data.len() {
            let label_len = data[pos] as usize;
            if label_len == 0 {
                break;
            }
            if label_len & 0xC0 == 0xC0 {
                jumps += 1;
                if jumps > 10 {
                    return true;
                }
                if pos + 1 >= data.len() {
                    break;
                }
                let ptr = (label_len & 0x3F) << 8 | data[pos + 1] as usize;
                if ptr >= data.len() {
                    break;
                }
                pos = ptr;
            } else {
                pos += 1 + label_len;
            }
        }
        false
    }
}

impl Detector for PixiefailDetector {
    fn name(&self) -> &str {
        "pixiefail"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Scan for DHCPv6 message structures
        let dhcpv6_msg_types = [DHCPV6_SOLICIT, DHCPV6_ADVERTISE, DHCPV6_REPLY];

        for i in 0..data.len().saturating_sub(8) {
            if dhcpv6_msg_types.contains(&data[i]) && data[i + 1..i + 4] != [0, 0, 0] {
                let option_start = i + 4;
                if option_start < data.len() {
                    findings.extend(self.check_dhcpv6_options(&data[option_start..], option_start));
                }
            }
            if findings.len() >= MAX_PIXIEFAIL_FINDINGS {
                break;
            }
        }

        // Check for IPv6 router advertisement anomalies (CVE-2023-45233)
        for i in 0..data.len().saturating_sub(16) {
            // ICMPv6 type 134 = Router Advertisement
            if data[i] == 134 && data[i + 1] == 0 && i + 16 < data.len() {
                // Hop limit sanity: routers advertise plausible hop limits
                // (64, 255, ...). A zero or arbitrary byte means the
                // candidate is not a Router Advertisement.
                let hop_limit = data[i + 4];
                if !matches!(hop_limit, 1 | 32 | 64 | 128 | 255) {
                    continue;
                }
                let option_area = &data[i + 16..];
                if option_area.len() >= 4 {
                    // Only trust option parsing when the option type is one
                    // defined for Router Advertisements (SLLA, MTU, prefix
                    // information, RDNSS, ...). Random (type, len=0) byte
                    // pairs are ubiquitous in firmware volumes.
                    let is_ra_option_type = matches!(option_area[0], 1..=5 | 25 | 26 | 31 | 39);
                    let opt_len = option_area[1] as usize * 8;
                    if is_ra_option_type && opt_len == 0 {
                        findings.push(
                            Finding::new(
                                "pixiefail",
                                Severity::High,
                                "PixieFail: IPv6 RA with zero-length option (CVE-2023-45233)",
                                &format!(
                                    "Router Advertisement at offset 0x{:08X} contains option \
                                         with length 0, causing infinite loop in option parser.",
                                    i
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", i),
                                "cve": "CVE-2023-45233",
                            })),
                        );
                    }
                }
            }
        }

        Ok(findings)
    }
}
