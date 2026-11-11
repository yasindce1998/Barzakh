use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::detector::{Detector, DetectorError, Finding, Severity};

const FV_SIGNATURE: &[u8] = b"_FVH";
const PE_MAGIC: [u8; 2] = [0x4D, 0x5A]; // "MZ"

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum TrustLevel {
    Trusted,
    PartiallyTrusted,
    Unknown,
    Suspicious,
    Malicious,
}

impl TrustLevel {
    fn as_str(&self) -> &str {
        match self {
            Self::Trusted => "trusted",
            Self::PartiallyTrusted => "partially_trusted",
            Self::Unknown => "unknown",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ComponentInfo {
    name: String,
    guid: Option<String>,
    hash_sha256: String,
    offset: usize,
    size: usize,
    has_authenticode: bool,
    file_type: u8,
    /// FFS header checksum validated (sum of header bytes, with the
    /// checksum and state fields zeroed, is zero). Real firmware files
    /// carry valid checksums; noise-parsed "files" do not.
    checksum_valid: bool,
}

#[derive(Debug, Clone)]
struct TrustScore {
    level: TrustLevel,
    score: f64,
    factors: HashMap<String, f64>,
}

// Weights for trust score computation
const WEIGHT_SIGNATURE: f64 = 0.40;
const WEIGHT_KNOWN_GUID: f64 = 0.25;
const WEIGHT_TRUSTED_CA: f64 = 0.20;
const WEIGHT_KNOWN_HASH: f64 = 0.15;

// Well-known UEFI firmware GUIDs (DXE Core, PEI Core, etc.)
const KNOWN_GUIDS: &[&str] = &[
    "5b1b31a1-9562-11d2-8e3f-00a0c969723b", // DXE Core
    "52c05b14-0b98-496c-bc3b-04b50211d680", // PEI Core
    "1ba0062e-c779-4582-8566-336ae8f78f09", // Security Core
    "462caa21-7614-4503-836e-8ab6f4662331", // DXE Dispatcher
    "a19832b9-ac25-11d3-9a2d-0090273fc14d", // BDS
    "7c04a583-9e3e-4f1c-ad65-e05268d0b4d1", // Shell
];

pub struct AttestationDetector;

impl Default for AttestationDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationDetector {
    pub fn new() -> Self {
        Self
    }

    fn extract_components(data: &[u8]) -> Vec<ComponentInfo> {
        let mut components = Vec::new();
        let mut pos = 0;

        while pos + 4 <= data.len() {
            if let Some(sig_offset) = data[pos..].windows(4).position(|w| w == FV_SIGNATURE) {
                let fvh_pos = pos + sig_offset;
                let fv_start = fvh_pos.saturating_sub(40);

                if fv_start + 56 > data.len() {
                    pos = fvh_pos + 4;
                    continue;
                }

                let fv_length = u64::from_le_bytes(
                    data[fv_start + 32..fv_start + 40]
                        .try_into()
                        .unwrap_or([0; 8]),
                ) as usize;

                let header_length = u16::from_le_bytes(
                    data[fv_start + 48..fv_start + 50]
                        .try_into()
                        .unwrap_or([0; 2]),
                ) as usize;

                let fv_end = if fv_length > 0 && fv_start + fv_length <= data.len() {
                    fv_start + fv_length
                } else {
                    (fv_start + 0x10000).min(data.len())
                };

                // Walk FFS files within this FV
                let ffs_start = fv_start + header_length.max(56);
                Self::walk_ffs_files(data, ffs_start, fv_end, &mut components);

                pos = fv_end;
            } else {
                break;
            }
        }

        components
    }

    fn walk_ffs_files(data: &[u8], start: usize, end: usize, components: &mut Vec<ComponentInfo>) {
        let mut pos = start;

        while pos + 24 <= end {
            // FFS file header is 24 bytes
            // Bytes 0-15: GUID
            // Byte 18: file type
            // Bytes 20-22: size (3 bytes LE)
            let guid_bytes: [u8; 16] = data[pos..pos + 16].try_into().unwrap_or([0; 16]);

            // Skip padding (all 0xFF or 0x00)
            if guid_bytes.iter().all(|&b| b == 0xFF) || guid_bytes.iter().all(|&b| b == 0x00) {
                pos += 8;
                continue;
            }

            let file_type = data[pos + 18];
            let size =
                u32::from_le_bytes([data[pos + 20], data[pos + 21], data[pos + 22], 0]) as usize;

            if size < 24 || pos + size > end {
                pos += 8;
                continue;
            }

            // PI FFS header checksum: sum of all 24 header bytes with the
            // header-checksum field (offset 16) and state field (offset 23)
            // treated as zero must be zero. This separates real firmware
            // files from byte sequences that merely parse.
            let checksum_valid = {
                let mut sum: u8 = 0;
                for (j, &b) in data[pos..pos + 24].iter().enumerate() {
                    if j != 16 && j != 23 {
                        sum = sum.wrapping_add(b);
                    }
                }
                sum == 0
            };
            if !checksum_valid {
                pos += 8;
                continue;
            }

            // PI FFS state byte: for a constructed, header-valid,
            // data-valid file the state is exactly 0xF8 (erase polarity 1)
            // or 0x07 (polarity 0). Noise that survives the checksum gate
            // lands on other values.
            let state = data[pos + 23];
            let state_valid = state == 0xF8 || state == 0x07;
            if !state_valid {
                pos += 8;
                continue;
            }

            // Real FFS files are 8-byte aligned within the volume (24-byte
            // header plus data padded to 8) and carry RFC 4122 GUIDs with
            // the variant bits (10xx xxxx) set. Noise that survives the
            // checksum and state gates fails one of these.
            if !size.is_multiple_of(8) || (guid_bytes[8] & 0xC0) != 0x80 {
                pos += 8;
                continue;
            }

            let guid_str = Self::format_guid(&guid_bytes);
            let file_data = &data[pos..pos + size];
            let hash = Self::sha256_hex(file_data);
            let has_authenticode = Self::check_authenticode(file_data);

            let name = Self::file_type_name(file_type);

            components.push(ComponentInfo {
                name: format!("{} [{}]", name, &guid_str[..8]),
                guid: Some(guid_str),
                hash_sha256: hash,
                offset: pos,
                size,
                has_authenticode,
                file_type,
                checksum_valid,
            });

            // Align to 8-byte boundary
            pos += (size + 7) & !7;
        }
    }

    fn check_authenticode(data: &[u8]) -> bool {
        // Look for PE within this FFS file and check for certificate table
        if data.len() < 64 {
            return false;
        }

        for offset in (0..data.len().saturating_sub(256)).step_by(16) {
            if offset + 2 <= data.len() && data[offset..offset + 2] == PE_MAGIC {
                let pe_start = offset;
                if pe_start + 0x40 > data.len() {
                    continue;
                }
                let e_lfanew = u32::from_le_bytes(
                    data[pe_start + 0x3C..pe_start + 0x40]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize;

                let pe_sig_offset = pe_start + e_lfanew;
                if pe_sig_offset + 4 > data.len()
                    || &data[pe_sig_offset..pe_sig_offset + 4] != b"PE\x00\x00"
                {
                    continue;
                }

                // Check optional header magic to determine PE32 vs PE32+
                let opt_offset = pe_sig_offset + 24;
                if opt_offset + 2 > data.len() {
                    continue;
                }
                let opt_magic = u16::from_le_bytes(
                    data[opt_offset..opt_offset + 2]
                        .try_into()
                        .unwrap_or([0; 2]),
                );

                // Certificate table entry in data directories
                let cert_dir_offset = match opt_magic {
                    0x10B => opt_offset + 128, // PE32: data dir[4] at offset 128
                    0x20B => opt_offset + 144, // PE32+: data dir[4] at offset 144
                    _ => continue,
                };

                if cert_dir_offset + 8 > data.len() {
                    continue;
                }

                let cert_rva = u32::from_le_bytes(
                    data[cert_dir_offset..cert_dir_offset + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                let cert_size = u32::from_le_bytes(
                    data[cert_dir_offset + 4..cert_dir_offset + 8]
                        .try_into()
                        .unwrap_or([0; 4]),
                );

                if cert_rva > 0 && cert_size > 0 {
                    return true;
                }
            }
        }
        false
    }

    fn compute_trust_score(component: &ComponentInfo) -> TrustScore {
        let mut factors = HashMap::new();
        let mut score = 0.0;

        // Factor 1: Authenticode signature
        let sig_score = if component.has_authenticode { 1.0 } else { 0.0 };
        factors.insert("signature".to_string(), sig_score);
        score += sig_score * WEIGHT_SIGNATURE;

        // Factor 2: Known GUID
        let guid_score = if let Some(ref guid) = component.guid {
            if KNOWN_GUIDS.contains(&guid.as_str()) {
                1.0
            } else {
                0.3
            }
        } else {
            0.0
        };
        factors.insert("known_guid".to_string(), guid_score);
        score += guid_score * WEIGHT_KNOWN_GUID;

        // Factor 3: Trusted CA (heuristic: signed implies trusted CA)
        let ca_score = if component.has_authenticode { 0.8 } else { 0.0 };
        factors.insert("trusted_ca".to_string(), ca_score);
        score += ca_score * WEIGHT_TRUSTED_CA;

        // Factor 4: Known hash (would need a hash database; use heuristic)
        let hash_score = 0.0; // No hash DB in offline mode
        factors.insert("known_hash".to_string(), hash_score);
        score += hash_score * WEIGHT_KNOWN_HASH;

        // Structural provenance: EDK2 FFS modules are not Authenticode
        // signed by design (integrity comes from the FV/FFS checksums and
        // measured boot), so a checksum-valid module inside a firmware
        // volume is at worst of unknown provenance — never "suspicious"
        // merely for lacking a signature. Suspicious requires a malformed
        // file type: a type outside the PI FFS specification inside a
        // checksum-valid file is injected structure.
        let known_type = matches!(component.file_type, 0x01..=0x0E | 0xF0);
        let level = if !known_type {
            TrustLevel::Suspicious
        } else if score >= 0.75 {
            TrustLevel::Trusted
        } else if score >= 0.50 {
            TrustLevel::PartiallyTrusted
        } else {
            TrustLevel::Unknown
        };

        TrustScore {
            level,
            score,
            factors,
        }
    }

    fn file_type_name(ft: u8) -> &'static str {
        match ft {
            0x01 => "RAW",
            0x02 => "FREEFORM",
            0x03 => "SECURITY_CORE",
            0x04 => "PEI_CORE",
            0x05 => "DXE_CORE",
            0x06 => "PEIM",
            0x07 => "DRIVER",
            0x09 => "APPLICATION",
            0x0B => "FV_IMAGE",
            _ => "UNKNOWN",
        }
    }

    fn format_guid(guid: &[u8; 16]) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]),
            u16::from_le_bytes([guid[4], guid[5]]),
            u16::from_le_bytes([guid[6], guid[7]]),
            guid[8],
            guid[9],
            guid[10],
            guid[11],
            guid[12],
            guid[13],
            guid[14],
            guid[15],
        )
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}

impl Detector for AttestationDetector {
    fn name(&self) -> &str {
        "attestation"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        let components = Self::extract_components(&data);

        if components.is_empty() {
            return Ok(findings);
        }

        let mut unsigned_count = 0;
        let mut suspicious_count = 0;
        let mut unknown_count = 0;

        for component in &components {
            let trust = Self::compute_trust_score(component);

            match trust.level {
                TrustLevel::Suspicious | TrustLevel::Malicious => {
                    suspicious_count += 1;
                    findings.push(
                        Finding::new(
                            "attestation",
                            Severity::High,
                            &format!("Suspicious component: {}", component.name),
                            &format!(
                                "Component '{}' at offset 0x{:08X} has trust score {:.2} ({}). \
                                 No valid signature or known provenance.",
                                component.name,
                                component.offset,
                                trust.score,
                                trust.level.as_str(),
                            ),
                        )
                        .with_confidence(0.75)
                        .with_details(serde_json::json!({
                            "component": component.name,
                            "guid": component.guid,
                            "hash": component.hash_sha256,
                            "offset": format!("0x{:08X}", component.offset),
                            "trust_score": trust.score,
                            "trust_level": trust.level.as_str(),
                            "factors": trust.factors,
                        }))
                        .with_recommendation(
                            "Investigate component provenance. May be injected malware.",
                        ),
                    );
                }
                TrustLevel::Unknown => {
                    unknown_count += 1;
                    // Only report critical file types as findings
                    if matches!(component.file_type, 0x03 | 0x04 | 0x05 | 0x07) {
                        findings.push(
                            Finding::new(
                                "attestation",
                                Severity::Medium,
                                &format!("Unknown provenance: {}", component.name),
                                &format!(
                                    "Critical component '{}' (type: {}) could not be verified. \
                                     Trust score: {:.2}.",
                                    component.name,
                                    Self::file_type_name(component.file_type),
                                    trust.score,
                                ),
                            )
                            .with_confidence(0.60)
                            .with_details(serde_json::json!({
                                "component": component.name,
                                "guid": component.guid,
                                "file_type": Self::file_type_name(component.file_type),
                                "trust_score": trust.score,
                            })),
                        );
                    }
                }
                _ => {}
            }

            if !component.has_authenticode {
                unsigned_count += 1;
            }
        }

        // Summary finding
        if unsigned_count > 0 || suspicious_count > 0 {
            findings.push(
                Finding::new(
                    "attestation",
                    if suspicious_count > 0 { Severity::High } else { Severity::Info },
                    "Firmware attestation summary",
                    &format!(
                        "Analyzed {} components: {} unsigned, {} suspicious, {} unknown provenance.",
                        components.len(),
                        unsigned_count,
                        suspicious_count,
                        unknown_count,
                    ),
                )
                .with_details(serde_json::json!({
                    "total_components": components.len(),
                    "unsigned": unsigned_count,
                    "suspicious": suspicious_count,
                    "unknown": unknown_count,
                })),
            );
        }

        Ok(findings)
    }
}
