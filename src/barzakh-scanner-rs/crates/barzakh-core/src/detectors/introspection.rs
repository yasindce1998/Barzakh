use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

#[allow(dead_code)]
const BST_ENTRY_SIZE: usize = 8;
const UEFI_DXE_RANGE: (u64, u64) = (0x0600_0000, 0x0800_0000);

struct BstEntry {
    name: &'static str,
    offset: usize,
    critical: bool,
}

const CRITICAL_BST_ENTRIES: &[BstEntry] = &[
    BstEntry {
        name: "RaiseTPL",
        offset: 0x18,
        critical: false,
    },
    BstEntry {
        name: "RestoreTPL",
        offset: 0x20,
        critical: false,
    },
    BstEntry {
        name: "AllocatePages",
        offset: 0x28,
        critical: false,
    },
    BstEntry {
        name: "FreePages",
        offset: 0x30,
        critical: false,
    },
    BstEntry {
        name: "GetMemoryMap",
        offset: 0x38,
        critical: false,
    },
    BstEntry {
        name: "AllocatePool",
        offset: 0x40,
        critical: false,
    },
    BstEntry {
        name: "FreePool",
        offset: 0x48,
        critical: false,
    },
    BstEntry {
        name: "CreateEvent",
        offset: 0x50,
        critical: false,
    },
    BstEntry {
        name: "SetTimer",
        offset: 0x58,
        critical: false,
    },
    BstEntry {
        name: "WaitForEvent",
        offset: 0x60,
        critical: false,
    },
    BstEntry {
        name: "SignalEvent",
        offset: 0x68,
        critical: false,
    },
    BstEntry {
        name: "CloseEvent",
        offset: 0x70,
        critical: false,
    },
    BstEntry {
        name: "CheckEvent",
        offset: 0x78,
        critical: false,
    },
    BstEntry {
        name: "InstallProtocolInterface",
        offset: 0x80,
        critical: false,
    },
    BstEntry {
        name: "ReinstallProtocolInterface",
        offset: 0x88,
        critical: false,
    },
    BstEntry {
        name: "UninstallProtocolInterface",
        offset: 0x90,
        critical: false,
    },
    BstEntry {
        name: "HandleProtocol",
        offset: 0x98,
        critical: false,
    },
    BstEntry {
        name: "RegisterProtocolNotify",
        offset: 0xA8,
        critical: false,
    },
    BstEntry {
        name: "LocateHandle",
        offset: 0xB0,
        critical: false,
    },
    BstEntry {
        name: "LocateDevicePath",
        offset: 0xB8,
        critical: false,
    },
    BstEntry {
        name: "InstallConfigurationTable",
        offset: 0xC0,
        critical: false,
    },
    BstEntry {
        name: "LoadImage",
        offset: 0xC8,
        critical: true,
    },
    BstEntry {
        name: "StartImage",
        offset: 0xD0,
        critical: true,
    },
    BstEntry {
        name: "Exit",
        offset: 0xD8,
        critical: false,
    },
    BstEntry {
        name: "UnloadImage",
        offset: 0xE0,
        critical: false,
    },
    BstEntry {
        name: "ExitBootServices",
        offset: 0xE8,
        critical: true,
    },
    BstEntry {
        name: "GetNextMonotonicCount",
        offset: 0xF0,
        critical: false,
    },
    BstEntry {
        name: "Stall",
        offset: 0xF8,
        critical: false,
    },
    BstEntry {
        name: "SetWatchdogTimer",
        offset: 0x100,
        critical: false,
    },
    BstEntry {
        name: "LocateProtocol",
        offset: 0x140,
        critical: true,
    },
];

// x86_64 trampoline patterns
struct TrampolinePattern {
    name: &'static str,
    prefix: &'static [u8],
    min_size: usize,
}

const TRAMPOLINE_PATTERNS: &[TrampolinePattern] = &[
    TrampolinePattern {
        name: "MOV RAX, imm64; JMP RAX",
        prefix: &[0x48, 0xB8],
        min_size: 12,
    },
    TrampolinePattern {
        name: "JMP [RIP+0]",
        prefix: &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00],
        min_size: 14,
    },
    TrampolinePattern {
        name: "PUSH imm32; RET",
        prefix: &[0x68],
        min_size: 6,
    },
    TrampolinePattern {
        name: "CALL [RIP+offset]",
        prefix: &[0xFF, 0x15],
        min_size: 6,
    },
];

pub struct LiveDetector;

impl Default for LiveDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl LiveDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_bst_region(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for BST signature
        let bst_sig: u64 = 0x56524553_544F4F42; // "BOOTSERV"
        let sig_bytes = bst_sig.to_le_bytes();

        let mut pos = 0;
        while pos + 8 <= data.len() {
            if data[pos..pos + 8] == sig_bytes {
                // Found BST, analyze function pointers
                for entry in CRITICAL_BST_ENTRIES {
                    let ptr_offset = pos + entry.offset;
                    if ptr_offset + 8 > data.len() {
                        continue;
                    }

                    let ptr = u64::from_le_bytes(
                        data[ptr_offset..ptr_offset + 8]
                            .try_into()
                            .unwrap_or([0; 8]),
                    );

                    if ptr == 0 {
                        continue;
                    }

                    // Check if pointer is outside expected UEFI DXE range
                    if ptr < UEFI_DXE_RANGE.0 || ptr > UEFI_DXE_RANGE.1 {
                        let severity = if entry.critical {
                            Severity::Critical
                        } else {
                            Severity::High
                        };

                        findings.push(
                            Finding::new(
                                "live",
                                severity,
                                &format!("BST hook: {} points outside DXE range", entry.name),
                                &format!(
                                    "Boot Services Table entry '{}' at BST+0x{:X} points to \
                                     0x{:016X}, which is outside the expected UEFI DXE region \
                                     (0x{:08X}-0x{:08X}). This strongly indicates a hook.",
                                    entry.name, entry.offset, ptr,
                                    UEFI_DXE_RANGE.0, UEFI_DXE_RANGE.1,
                                ),
                            )
                            .with_confidence(if entry.critical { 0.92 } else { 0.80 })
                            .with_details(serde_json::json!({
                                "service": entry.name,
                                "bst_offset": format!("0x{:X}", entry.offset),
                                "pointer": format!("0x{:016X}", ptr),
                                "expected_range": format!("0x{:08X}-0x{:08X}", UEFI_DXE_RANGE.0, UEFI_DXE_RANGE.1),
                                "critical": entry.critical,
                            }))
                            .with_recommendation(
                                "BST hook detected. Analyze the hook target for bootkit behavior.",
                            ),
                        );

                        // Check if the hook target is within the file and analyze it
                        if let Some(hook_data) = self.get_hook_code(data, ptr, pos) {
                            findings.extend(self.analyze_hook_code(hook_data, entry.name, ptr));
                        }
                    }
                }
            }
            pos += 8;
        }

        findings
    }

    fn get_hook_code<'a>(&self, data: &'a [u8], ptr: u64, bst_pos: usize) -> Option<&'a [u8]> {
        // Try to find the hook code within the memory dump
        // Heuristic: if ptr is a reasonable offset from BST, look there
        let base_estimate = bst_pos as u64 - 0x1000;
        if ptr > base_estimate {
            let offset = (ptr - base_estimate) as usize;
            if offset + 64 <= data.len() {
                return Some(&data[offset..offset + 64]);
            }
        }
        None
    }

    fn analyze_hook_code(&self, code: &[u8], service_name: &str, address: u64) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for trampoline patterns
        for pattern in TRAMPOLINE_PATTERNS {
            if code.len() >= pattern.min_size && code[..pattern.prefix.len()] == *pattern.prefix {
                let target = self.extract_trampoline_target(code, pattern);
                findings.push(
                    Finding::new(
                        "live",
                        Severity::Critical,
                        &format!("Trampoline in {} hook: {}", service_name, pattern.name),
                        &format!(
                            "Hook at 0x{:016X} for service '{}' uses trampoline pattern '{}'. \
                             Target: 0x{:016X}. This is a common bootkit hooking technique.",
                            address, service_name, pattern.name, target,
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "service": service_name,
                        "hook_address": format!("0x{:016X}", address),
                        "pattern": pattern.name,
                        "target": format!("0x{:016X}", target),
                    })),
                );
                break;
            }
        }

        // Check for NOP sleds (code injection indicator)
        let nop_count = code.iter().filter(|&&b| b == 0x90).count();
        if nop_count > 8 {
            findings.push(
                Finding::new(
                    "live",
                    Severity::Medium,
                    &format!("NOP sled near {} hook", service_name),
                    &format!(
                        "Found {} NOP (0x90) instructions near hook at 0x{:016X}. \
                         NOP sleds are commonly used for code injection alignment.",
                        nop_count, address,
                    ),
                )
                .with_confidence(0.65)
                .with_details(serde_json::json!({
                    "service": service_name,
                    "nop_count": nop_count,
                    "hook_address": format!("0x{:016X}", address),
                })),
            );
        }

        findings
    }

    fn extract_trampoline_target(&self, code: &[u8], pattern: &TrampolinePattern) -> u64 {
        match pattern.prefix {
            // MOV RAX, imm64; JMP RAX
            [0x48, 0xB8] if code.len() >= 10 => {
                u64::from_le_bytes(code[2..10].try_into().unwrap_or([0; 8]))
            }
            // JMP [RIP+0]
            [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00] if code.len() >= 14 => {
                u64::from_le_bytes(code[6..14].try_into().unwrap_or([0; 8]))
            }
            // PUSH imm32; RET
            [0x68] if code.len() >= 5 => {
                u32::from_le_bytes(code[1..5].try_into().unwrap_or([0; 4])) as u64
            }
            _ => 0,
        }
    }

    fn detect_code_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for PE headers at unusual page-aligned positions
        let page_size = 0x1000;
        for offset in (0..data.len().saturating_sub(256)).step_by(page_size) {
            if data[offset] == 0x4D && data[offset + 1] == 0x5A {
                // Found MZ header - check if it's in a suspicious location
                if offset > 0x100000 {
                    // Beyond typical firmware regions
                    let pe_offset_val = if offset + 0x40 <= data.len() {
                        u32::from_le_bytes(
                            data[offset + 0x3C..offset + 0x40]
                                .try_into()
                                .unwrap_or([0; 4]),
                        ) as usize
                    } else {
                        0
                    };

                    if pe_offset_val > 0
                        && offset + pe_offset_val + 4 <= data.len()
                        && &data[offset + pe_offset_val..offset + pe_offset_val + 4]
                            == b"PE\x00\x00"
                    {
                        findings.push(
                            Finding::new(
                                "live",
                                Severity::High,
                                &format!("Injected PE at offset 0x{:08X}", offset),
                                &format!(
                                    "Valid PE/COFF image found at memory offset 0x{:08X}, \
                                     which is in a non-standard location. This may be injected \
                                     bootkit code.",
                                    offset,
                                ),
                            )
                            .with_confidence(0.70)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", offset),
                                "pe_offset": pe_offset_val,
                            }))
                            .with_recommendation(
                                "Extract and analyze the PE image for malicious behavior.",
                            ),
                        );
                    }
                }
            }
        }

        findings
    }
}

impl Detector for LiveDetector {
    fn name(&self) -> &str {
        "live"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.analyze_bst_region(&data));
        findings.extend(self.detect_code_injection(&data));

        Ok(findings)
    }
}
