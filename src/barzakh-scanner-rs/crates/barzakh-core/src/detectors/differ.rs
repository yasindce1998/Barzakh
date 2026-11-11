use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

const FV_SIGNATURE: &[u8] = b"_FVH";
#[allow(dead_code)]
const PE_MAGIC: &[u8] = b"MZ";

#[derive(Debug, Clone, PartialEq)]
enum DiffType {
    Unchanged,
    Added,
    Removed,
    Modified,
    Relocated,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FirmwareVolume {
    offset: usize,
    size: usize,
    guid: [u8; 16],
    hash: String,
}

#[derive(Debug, Clone)]
struct VolumeDiff {
    guid: [u8; 16],
    diff_type: DiffType,
    baseline_offset: Option<usize>,
    target_offset: Option<usize>,
    sections_changed: Vec<String>,
}

pub struct FirmwareDifferDetector {
    baseline: Option<Baseline>,
}

impl FirmwareDifferDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }

    fn parse_firmware_volumes(data: &[u8]) -> Vec<FirmwareVolume> {
        let mut volumes = Vec::new();
        let mut pos = 0;

        while pos + 4 <= data.len() {
            if let Some(sig_offset) = data[pos..].windows(4).position(|w| w == FV_SIGNATURE) {
                let fvh_pos = pos + sig_offset;
                // FV header starts 40 bytes before _FVH signature
                let fv_start = fvh_pos.saturating_sub(40);

                if fv_start + 56 > data.len() {
                    pos = fvh_pos + 4;
                    continue;
                }

                // Read GUID at offset 0 of FV header (16 bytes)
                let mut guid = [0u8; 16];
                guid.copy_from_slice(&data[fv_start..fv_start + 16]);

                // Read FV length at offset 32 (8 bytes, u64)
                let fv_length = u64::from_le_bytes(
                    data[fv_start + 32..fv_start + 40]
                        .try_into()
                        .unwrap_or([0; 8]),
                ) as usize;

                let actual_size = if fv_length > 0 && fv_start + fv_length <= data.len() {
                    fv_length
                } else {
                    // Fallback: use 64KB or remaining data
                    (data.len() - fv_start).min(0x10000)
                };

                let hash = Self::sha256_hex(&data[fv_start..fv_start + actual_size]);

                volumes.push(FirmwareVolume {
                    offset: fv_start,
                    size: actual_size,
                    guid,
                    hash,
                });

                pos = fv_start + actual_size;
            } else {
                break;
            }
        }

        volumes
    }

    fn diff_volumes(
        baseline_vols: &[FirmwareVolume],
        target_vols: &[FirmwareVolume],
    ) -> Vec<VolumeDiff> {
        let mut diffs = Vec::new();
        let mut matched_target: Vec<bool> = vec![false; target_vols.len()];

        for bv in baseline_vols {
            // Find matching volume by GUID
            if let Some((tidx, tv)) = target_vols
                .iter()
                .enumerate()
                .find(|(i, tv)| tv.guid == bv.guid && !matched_target[*i])
            {
                matched_target[tidx] = true;

                if bv.hash == tv.hash {
                    let diff_type = if bv.offset != tv.offset {
                        DiffType::Relocated
                    } else {
                        DiffType::Unchanged
                    };
                    diffs.push(VolumeDiff {
                        guid: bv.guid,
                        diff_type,
                        baseline_offset: Some(bv.offset),
                        target_offset: Some(tv.offset),
                        sections_changed: Vec::new(),
                    });
                } else {
                    diffs.push(VolumeDiff {
                        guid: bv.guid,
                        diff_type: DiffType::Modified,
                        baseline_offset: Some(bv.offset),
                        target_offset: Some(tv.offset),
                        sections_changed: Vec::new(),
                    });
                }
            } else {
                diffs.push(VolumeDiff {
                    guid: bv.guid,
                    diff_type: DiffType::Removed,
                    baseline_offset: Some(bv.offset),
                    target_offset: None,
                    sections_changed: Vec::new(),
                });
            }
        }

        // Remaining unmatched targets are additions
        for (i, tv) in target_vols.iter().enumerate() {
            if !matched_target[i] {
                diffs.push(VolumeDiff {
                    guid: tv.guid,
                    diff_type: DiffType::Added,
                    baseline_offset: None,
                    target_offset: Some(tv.offset),
                    sections_changed: Vec::new(),
                });
            }
        }

        diffs
    }

    #[allow(dead_code)]
    fn find_pe_section_changes(baseline_data: &[u8], target_data: &[u8]) -> Vec<String> {
        let mut changed = Vec::new();

        let b_sections = Self::parse_pe_sections(baseline_data);
        let t_sections = Self::parse_pe_sections(target_data);

        for (name, b_hash) in &b_sections {
            if let Some(t_hash) = t_sections.get(name.as_str()) {
                if b_hash != t_hash {
                    changed.push(format!("section_modified({})", name));
                }
            } else {
                changed.push(format!("section_removed({})", name));
            }
        }

        for name in t_sections.keys() {
            if !b_sections.contains_key(name.as_str()) {
                changed.push(format!("section_added({})", name));
            }
        }

        changed
    }

    #[allow(dead_code)]
    fn parse_pe_sections(data: &[u8]) -> HashMap<String, String> {
        let mut sections = HashMap::new();

        if data.len() < 64 || &data[0..2] != PE_MAGIC {
            return sections;
        }

        // e_lfanew at offset 0x3C
        let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;

        if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            return sections;
        }

        // Number of sections at PE + 6
        let num_sections = u16::from_le_bytes(
            data[pe_offset + 6..pe_offset + 8]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;

        // Size of optional header at PE + 20
        let opt_header_size = u16::from_le_bytes(
            data[pe_offset + 20..pe_offset + 22]
                .try_into()
                .unwrap_or([0; 2]),
        ) as usize;

        // Section headers start after optional header
        let sections_start = pe_offset + 24 + opt_header_size;

        for i in 0..num_sections {
            let sh_offset = sections_start + i * 40;
            if sh_offset + 40 > data.len() {
                break;
            }

            // Section name (8 bytes, null-terminated)
            let name_bytes = &data[sh_offset..sh_offset + 8];
            let name = std::str::from_utf8(name_bytes)
                .unwrap_or("")
                .trim_end_matches('\0')
                .to_string();

            // Raw data offset and size
            let raw_size = u32::from_le_bytes(
                data[sh_offset + 16..sh_offset + 20]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;
            let raw_offset = u32::from_le_bytes(
                data[sh_offset + 20..sh_offset + 24]
                    .try_into()
                    .unwrap_or([0; 4]),
            ) as usize;

            if raw_offset + raw_size <= data.len() && raw_size > 0 {
                let section_data = &data[raw_offset..raw_offset + raw_size];
                sections.insert(name, Self::sha256_hex(section_data));
            }
        }

        sections
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

    fn guid_to_string(guid: &[u8; 16]) -> String {
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
}

impl Detector for FirmwareDifferDetector {
    fn name(&self) -> &str {
        "firmware_differ"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let target_data = context.shared_bytes();
        let mut findings = Vec::new();

        let baseline = match &self.baseline {
            Some(b) => b,
            None => {
                return Err(DetectorError::NotApplicable(
                    "no baseline configured".into(),
                ))
            }
        };

        // Get baseline firmware path from baseline data
        let baseline_path = match &baseline.boot_services_table {
            Some(bst) => match bst.get("baseline_firmware_path").and_then(|v| v.as_str()) {
                Some(p) => p.to_string(),
                None => {
                    return Err(DetectorError::NotApplicable(
                        "baseline has no firmware path".into(),
                    ))
                }
            },
            None => {
                return Err(DetectorError::NotApplicable(
                    "baseline has no firmware path".into(),
                ))
            }
        };

        let baseline_data = crate::ScanContext::load(Path::new(&baseline_path))?;

        let baseline_vols = Self::parse_firmware_volumes(baseline_data.data());
        let target_vols = Self::parse_firmware_volumes(&target_data);

        let diffs = Self::diff_volumes(&baseline_vols, &target_vols);

        for diff in &diffs {
            match diff.diff_type {
                DiffType::Added => {
                    findings.push(
                        Finding::new(
                            "firmware_differ",
                            Severity::High,
                            &format!(
                                "New firmware volume added: {}",
                                Self::guid_to_string(&diff.guid)
                            ),
                            "A firmware volume present in the target was not found in the \
                             baseline. This may indicate injected malicious firmware modules.",
                        )
                        .with_confidence(0.80)
                        .with_details(serde_json::json!({
                            "guid": Self::guid_to_string(&diff.guid),
                            "diff_type": "added",
                            "target_offset": diff.target_offset,
                        }))
                        .with_recommendation(
                            "New firmware volume detected. Verify this is an authorized update.",
                        ),
                    );
                }
                DiffType::Removed => {
                    findings.push(
                        Finding::new(
                            "firmware_differ",
                            Severity::Medium,
                            &format!(
                                "Firmware volume removed: {}",
                                Self::guid_to_string(&diff.guid)
                            ),
                            "A firmware volume present in the baseline is missing from target.",
                        )
                        .with_confidence(0.75)
                        .with_details(serde_json::json!({
                            "guid": Self::guid_to_string(&diff.guid),
                            "diff_type": "removed",
                            "baseline_offset": diff.baseline_offset,
                        })),
                    );
                }
                DiffType::Modified => {
                    let severity = Severity::High;
                    findings.push(
                        Finding::new(
                            "firmware_differ",
                            severity,
                            &format!(
                                "Firmware volume modified: {}",
                                Self::guid_to_string(&diff.guid)
                            ),
                            "A firmware volume's content differs between baseline and target. \
                             This indicates the firmware has been changed.",
                        )
                        .with_confidence(0.85)
                        .with_details(serde_json::json!({
                            "guid": Self::guid_to_string(&diff.guid),
                            "diff_type": "modified",
                            "baseline_offset": diff.baseline_offset,
                            "target_offset": diff.target_offset,
                            "sections_changed": diff.sections_changed,
                        }))
                        .with_recommendation(
                            "Firmware volume content changed. Determine if this is a \
                             legitimate update or unauthorized modification.",
                        ),
                    );
                }
                DiffType::Relocated => {
                    findings.push(
                        Finding::new(
                            "firmware_differ",
                            Severity::Low,
                            &format!(
                                "Firmware volume relocated: {}",
                                Self::guid_to_string(&diff.guid)
                            ),
                            "A firmware volume has moved to a different offset but content \
                             is unchanged. May indicate firmware layout reorganization.",
                        )
                        .with_confidence(0.70)
                        .with_details(serde_json::json!({
                            "guid": Self::guid_to_string(&diff.guid),
                            "diff_type": "relocated",
                            "baseline_offset": diff.baseline_offset,
                            "target_offset": diff.target_offset,
                        })),
                    );
                }
                DiffType::Unchanged => {}
            }
        }

        // Summary finding
        let added = diffs
            .iter()
            .filter(|d| d.diff_type == DiffType::Added)
            .count();
        let removed = diffs
            .iter()
            .filter(|d| d.diff_type == DiffType::Removed)
            .count();
        let modified = diffs
            .iter()
            .filter(|d| d.diff_type == DiffType::Modified)
            .count();

        if added > 0 || removed > 0 || modified > 0 {
            findings.push(
                Finding::new(
                    "firmware_differ",
                    Severity::Info,
                    "Firmware diff summary",
                    &format!(
                        "Compared {} baseline volumes against {} target volumes: \
                         {} added, {} removed, {} modified.",
                        baseline_vols.len(),
                        target_vols.len(),
                        added,
                        removed,
                        modified,
                    ),
                )
                .with_details(serde_json::json!({
                    "baseline_volumes": baseline_vols.len(),
                    "target_volumes": target_vols.len(),
                    "added": added,
                    "removed": removed,
                    "modified": modified,
                })),
            );
        }

        Ok(findings)
    }
}
