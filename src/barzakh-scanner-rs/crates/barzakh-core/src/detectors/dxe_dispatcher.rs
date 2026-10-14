use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const EFI_DEP_PUSH: u8 = 0x02;
const EFI_DEP_AND: u8 = 0x03;
const EFI_DEP_OR: u8 = 0x04;
const EFI_DEP_NOT: u8 = 0x05;
const EFI_DEP_TRUE: u8 = 0x06;
const EFI_DEP_FALSE: u8 = 0x07;
const EFI_DEP_END: u8 = 0x08;
const EFI_DEP_SOR: u8 = 0x09;

const EFI_FV_FILETYPE_DXE_CORE: u8 = 0x05;
const EFI_FV_FILETYPE_DRIVER: u8 = 0x07;

const DEPEX_SECTION_TYPE: u8 = 0x13;

pub struct DxeDispatcherDetector;

impl Default for DxeDispatcherDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DxeDispatcherDetector {
    pub fn new() -> Self {
        Self
    }

    fn validate_depex(&self, data: &[u8], offset: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut pos = 0;
        let mut stack_depth: i32 = 0;
        let mut guid_count = 0;
        let mut has_sor = false;
        // Number of complete PUSH+GUID pairs parsed so far: an invalid
        // opcode is only meaningful after the expression has demonstrated
        // that it is a real dependency (random `xx xx xx 13` section-like
        // bytes parse zero pushes before stumbling on a bad opcode).
        let mut completed_pushes = 0usize;

        while pos < data.len() {
            let opcode = data[pos];
            match opcode {
                EFI_DEP_PUSH => {
                    if pos + 17 > data.len() {
                        break;
                    }
                    stack_depth += 1;
                    guid_count += 1;
                    pos += 17; // opcode + 16-byte GUID
                    completed_pushes += 1;
                }
                EFI_DEP_AND | EFI_DEP_OR => {
                    stack_depth -= 1;
                    pos += 1;
                }
                EFI_DEP_NOT => {
                    pos += 1;
                }
                EFI_DEP_TRUE | EFI_DEP_FALSE => {
                    stack_depth += 1;
                    pos += 1;
                }
                EFI_DEP_END => {
                    break;
                }
                EFI_DEP_SOR => {
                    has_sor = true;
                    pos += 1;
                }
                _ => {
                    // An invalid opcode inside an expression that has not
                    // yet parsed real dependency structure is noise, not a
                    // tampered depex.
                    if completed_pushes < 2 {
                        break;
                    }
                    findings.push(
                        Finding::new(
                            "dxe_dispatcher",
                            Severity::High,
                            "DXE Dispatcher: Invalid dependency expression opcode",
                            &format!(
                                "Dependency expression at offset 0x{:08X} contains invalid opcode \
                                 0x{:02X} at position {}. May indicate depex tampering to alter \
                                 DXE driver load order.",
                                offset, opcode, pos
                            ),
                        )
                        .with_confidence(0.82)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", offset),
                            "invalid_opcode": format!("0x{:02X}", opcode),
                            "position_in_depex": pos,
                        }))
                        .with_recommendation(
                            "Verify firmware volume integrity and re-flash if tampered",
                        ),
                    );
                    return findings;
                }
            }
        }

        // Check for unreasonably large dependency chains
        if guid_count > 32 {
            findings.push(
                Finding::new(
                    "dxe_dispatcher",
                    Severity::Medium,
                    "DXE Dispatcher: Excessive dependency chain length",
                    &format!(
                        "Dependency expression at offset 0x{:08X} references {} GUIDs. \
                         Abnormally long chains may be used to create ordering exploits.",
                        offset, guid_count
                    ),
                )
                .with_confidence(0.60)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "guid_count": guid_count,
                    "has_sor": has_sor,
                })),
            );
        }

        // Stack imbalance indicates corrupted depex
        if stack_depth != 1 && guid_count > 0 {
            findings.push(
                Finding::new(
                    "dxe_dispatcher",
                    Severity::High,
                    "DXE Dispatcher: Dependency expression stack imbalance",
                    &format!(
                        "Dependency expression at offset 0x{:08X} ends with stack depth {} \
                         (expected 1). The depex is malformed and may cause unpredictable \
                         driver dispatch behavior.",
                        offset, stack_depth
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", offset),
                    "final_stack_depth": stack_depth,
                    "guid_count": guid_count,
                })),
            );
        }

        // SOR (Schedule on Request) is unusual and may indicate prioritization manipulation
        if has_sor && guid_count > 0 {
            findings.push(
                Finding::new(
                    "dxe_dispatcher",
                    Severity::Low,
                    "DXE Dispatcher: Schedule-on-Request dependency found",
                    &format!(
                        "Dependency expression at offset 0x{:08X} uses SOR opcode. This defers \
                         driver loading until explicitly requested, which is unusual and may \
                         indicate load-order manipulation.",
                        offset
                    ),
                )
                .with_confidence(0.45),
            );
        }

        findings
    }
}

impl Detector for DxeDispatcherDetector {
    fn name(&self) -> &str {
        "dxe_dispatcher"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        // Scan for DXE dependency expression sections
        // FFS section header: Size(3) + Type(1), where Type=0x13 is DEPEX
        for i in 0..data.len().saturating_sub(20) {
            let section_size = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], 0]) as usize;
            let section_type = data[i + 3];

            if section_type == DEPEX_SECTION_TYPE
                && section_size > 4
                && section_size < 0x10000
                && i + section_size <= data.len()
            {
                let depex_data = &data[i + 4..i + section_size];
                // Validate it starts with a valid opcode
                if !depex_data.is_empty()
                    && (depex_data[0] == EFI_DEP_PUSH
                        || depex_data[0] == EFI_DEP_TRUE
                        || depex_data[0] == EFI_DEP_SOR)
                {
                    findings.extend(self.validate_depex(depex_data, i + 4));
                }
            }
        }

        // Check for DXE driver files with suspicious characteristics
        let fv_sig = b"_FVH";
        for i in 0..data.len().saturating_sub(56) {
            if &data[i..i + 4] == fv_sig {
                let fv_start = i.saturating_sub(40);
                // Scan FFS headers within FV for DXE drivers
                let header_len = u16::from_le_bytes(
                    data[fv_start + 48..fv_start + 50]
                        .try_into()
                        .unwrap_or([0; 2]),
                ) as usize;

                if header_len > 0 && fv_start + header_len < data.len() {
                    let ffs_start = fv_start + header_len;
                    // Check first few FFS files
                    let mut ffs_pos = ffs_start;
                    let mut driver_count = 0;
                    while ffs_pos + 24 < data.len() && driver_count < 200 {
                        let file_type = data[ffs_pos + 18];
                        if file_type == EFI_FV_FILETYPE_DRIVER
                            || file_type == EFI_FV_FILETYPE_DXE_CORE
                        {
                            driver_count += 1;
                        }
                        let ffs_size = u32::from_le_bytes([
                            data[ffs_pos + 20],
                            data[ffs_pos + 21],
                            data[ffs_pos + 22],
                            0,
                        ]) as usize;
                        if !(24..=0x1000000).contains(&ffs_size) {
                            break;
                        }
                        ffs_pos += (ffs_size + 7) & !7; // 8-byte aligned
                    }
                }
            }
        }

        Ok(findings)
    }
}
