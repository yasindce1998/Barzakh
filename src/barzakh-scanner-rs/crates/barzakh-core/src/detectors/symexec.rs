use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};
use crate::symengine::{SinkKind, SymConfig, SymEngine};

#[allow(dead_code)]
const PE_MAGIC: [u8; 2] = [0x4D, 0x5A];

#[derive(Debug, Clone, Copy, PartialEq)]
enum HookBehavior {
    Passthrough,
    Interception,
    Persistence,
    DataExfiltration,
    CodeInjection,
    Unknown,
}

impl HookBehavior {
    fn as_str(&self) -> &str {
        match self {
            Self::Passthrough => "passthrough",
            Self::Interception => "interception",
            Self::Persistence => "persistence",
            Self::DataExfiltration => "data_exfiltration",
            Self::CodeInjection => "code_injection",
            Self::Unknown => "unknown",
        }
    }

    fn severity(&self) -> Severity {
        match self {
            Self::Passthrough => Severity::Low,
            Self::Interception => Severity::High,
            Self::Persistence => Severity::Critical,
            Self::DataExfiltration => Severity::Critical,
            Self::CodeInjection => Severity::Critical,
            Self::Unknown => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct BasicBlock {
    start: usize,
    end: usize,
    instructions: Vec<Instruction>,
    successors: Vec<usize>,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct Instruction {
    offset: usize,
    bytes: Vec<u8>,
    mnemonic: InstructionType,
    operand_value: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)]
enum InstructionType {
    Call,
    Jump,
    ConditionalJump,
    Return,
    Move,
    Push,
    Pop,
    Lea,
    Cmp,
    Test,
    Nop,
    Out,
    In,
    Syscall,
    Other,
}

#[allow(dead_code)]
struct BstWritePattern {
    name: &'static str,
    bytes: &'static [u8],
    behavior: HookBehavior,
}

const BST_WRITE_PATTERNS: &[BstWritePattern] = &[
    // MOV [reg+offset], reg — direct pointer overwrite
    BstWritePattern {
        name: "direct_pointer_write",
        bytes: &[0x48, 0x89],
        behavior: HookBehavior::Interception,
    },
    // XCHG [reg], reg — atomic swap (save original, install hook)
    BstWritePattern {
        name: "atomic_swap",
        bytes: &[0x48, 0x87],
        behavior: HookBehavior::Interception,
    },
    // LEA + MOV pattern (load address of hook, store to BST)
    BstWritePattern {
        name: "lea_mov_install",
        bytes: &[0x48, 0x8D],
        behavior: HookBehavior::Interception,
    },
];

// Patterns indicating persistence behavior
const PERSISTENCE_INDICATORS: &[&[u8]] = &[
    b"SetVariable",
    b"WriteFlash",
    b"SpiWrite",
    b"NvramWrite",
    b"EFI_VARIABLE",
];

// Patterns indicating data exfiltration
const EXFIL_INDICATORS: &[&[u8]] = &[
    b"NetworkProtocol",
    b"SimpleNetwork",
    b"TcpProtocol",
    b"UdpProtocol",
    b"HttpProtocol",
];

pub struct SymExecDetector;

impl Default for SymExecDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl SymExecDetector {
    pub fn new() -> Self {
        Self
    }

    fn analyze_code_region(&self, data: &[u8], offset: usize) -> Vec<BasicBlock> {
        let mut blocks = Vec::new();
        let mut current_block = BasicBlock {
            start: offset,
            end: offset,
            instructions: Vec::new(),
            successors: Vec::new(),
        };

        let mut pos = 0;
        let max_analyze = data.len().min(4096); // Analyze up to 4KB per region

        while pos < max_analyze {
            let inst = self.decode_instruction(data, pos);
            let inst_size = inst.bytes.len().max(1);

            match inst.mnemonic {
                InstructionType::Return => {
                    current_block.instructions.push(inst);
                    current_block.end = offset + pos + inst_size;
                    blocks.push(current_block.clone());
                    current_block = BasicBlock {
                        start: offset + pos + inst_size,
                        end: offset + pos + inst_size,
                        instructions: Vec::new(),
                        successors: Vec::new(),
                    };
                }
                InstructionType::Jump => {
                    current_block.instructions.push(inst.clone());
                    current_block.end = offset + pos + inst_size;
                    if let Some(target) = inst.operand_value {
                        current_block.successors.push(target as usize);
                    }
                    blocks.push(current_block.clone());
                    current_block = BasicBlock {
                        start: offset + pos + inst_size,
                        end: offset + pos + inst_size,
                        instructions: Vec::new(),
                        successors: Vec::new(),
                    };
                }
                InstructionType::ConditionalJump => {
                    current_block.instructions.push(inst.clone());
                    current_block.end = offset + pos + inst_size;
                    current_block.successors.push(offset + pos + inst_size);
                    if let Some(target) = inst.operand_value {
                        current_block.successors.push(target as usize);
                    }
                    blocks.push(current_block.clone());
                    current_block = BasicBlock {
                        start: offset + pos + inst_size,
                        end: offset + pos + inst_size,
                        instructions: Vec::new(),
                        successors: Vec::new(),
                    };
                }
                _ => {
                    current_block.instructions.push(inst);
                }
            }

            pos += inst_size;
        }

        if !current_block.instructions.is_empty() {
            current_block.end = offset + pos;
            blocks.push(current_block);
        }

        blocks
    }

    fn decode_instruction(&self, data: &[u8], pos: usize) -> Instruction {
        if pos >= data.len() {
            return Instruction {
                offset: pos,
                bytes: vec![0],
                mnemonic: InstructionType::Other,
                operand_value: None,
            };
        }

        let has_rex_w = pos + 1 < data.len() && (data[pos] & 0xF0 == 0x40);
        let opcode_pos = if has_rex_w { pos + 1 } else { pos };
        let opcode = if opcode_pos < data.len() {
            data[opcode_pos]
        } else {
            0
        };

        match opcode {
            0xC3 | 0xCB => Instruction {
                offset: pos,
                bytes: data[pos..=(opcode_pos)].to_vec(),
                mnemonic: InstructionType::Return,
                operand_value: None,
            },
            0xE8 => {
                // CALL rel32
                let size = opcode_pos - pos + 5;
                if opcode_pos + 5 <= data.len() {
                    let rel = i32::from_le_bytes(
                        data[opcode_pos + 1..opcode_pos + 5]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let target = (opcode_pos as i64 + 5 + rel as i64) as u64;
                    Instruction {
                        offset: pos,
                        bytes: data[pos..pos + size].to_vec(),
                        mnemonic: InstructionType::Call,
                        operand_value: Some(target),
                    }
                } else {
                    Instruction {
                        offset: pos,
                        bytes: vec![data[pos]],
                        mnemonic: InstructionType::Other,
                        operand_value: None,
                    }
                }
            }
            0xE9 => {
                // JMP rel32
                let size = opcode_pos - pos + 5;
                if opcode_pos + 5 <= data.len() {
                    let rel = i32::from_le_bytes(
                        data[opcode_pos + 1..opcode_pos + 5]
                            .try_into()
                            .unwrap_or([0; 4]),
                    );
                    let target = (opcode_pos as i64 + 5 + rel as i64) as u64;
                    Instruction {
                        offset: pos,
                        bytes: data[pos..pos + size].to_vec(),
                        mnemonic: InstructionType::Jump,
                        operand_value: Some(target),
                    }
                } else {
                    Instruction {
                        offset: pos,
                        bytes: vec![data[pos]],
                        mnemonic: InstructionType::Other,
                        operand_value: None,
                    }
                }
            }
            0xEB => {
                // JMP rel8
                if opcode_pos + 2 <= data.len() {
                    let rel = data[opcode_pos + 1] as i8;
                    let target = (opcode_pos as i64 + 2 + rel as i64) as u64;
                    let size = opcode_pos - pos + 2;
                    Instruction {
                        offset: pos,
                        bytes: data[pos..pos + size].to_vec(),
                        mnemonic: InstructionType::Jump,
                        operand_value: Some(target),
                    }
                } else {
                    Instruction {
                        offset: pos,
                        bytes: vec![data[pos]],
                        mnemonic: InstructionType::Other,
                        operand_value: None,
                    }
                }
            }
            0x70..=0x7F => {
                // Jcc rel8
                if opcode_pos + 2 <= data.len() {
                    let rel = data[opcode_pos + 1] as i8;
                    let target = (opcode_pos as i64 + 2 + rel as i64) as u64;
                    let size = opcode_pos - pos + 2;
                    Instruction {
                        offset: pos,
                        bytes: data[pos..pos + size].to_vec(),
                        mnemonic: InstructionType::ConditionalJump,
                        operand_value: Some(target),
                    }
                } else {
                    Instruction {
                        offset: pos,
                        bytes: vec![data[pos]],
                        mnemonic: InstructionType::Other,
                        operand_value: None,
                    }
                }
            }
            0xFF => {
                // FF /2 = CALL, FF /4 = JMP
                if opcode_pos + 2 <= data.len() {
                    let modrm = data[opcode_pos + 1];
                    let reg = (modrm >> 3) & 7;
                    let mnemonic = match reg {
                        2 => InstructionType::Call,
                        4 => InstructionType::Jump,
                        _ => InstructionType::Other,
                    };
                    let size = opcode_pos - pos + 2;
                    Instruction {
                        offset: pos,
                        bytes: data[pos..pos + size].to_vec(),
                        mnemonic,
                        operand_value: None,
                    }
                } else {
                    Instruction {
                        offset: pos,
                        bytes: vec![data[pos]],
                        mnemonic: InstructionType::Other,
                        operand_value: None,
                    }
                }
            }
            0x90 => Instruction {
                offset: pos,
                bytes: data[pos..=opcode_pos].to_vec(),
                mnemonic: InstructionType::Nop,
                operand_value: None,
            },
            0xE6 | 0xE7 => Instruction {
                offset: pos,
                bytes: data[pos..=opcode_pos].to_vec(),
                mnemonic: InstructionType::Out,
                operand_value: None,
            },
            0xE4 | 0xE5 => Instruction {
                offset: pos,
                bytes: data[pos..=opcode_pos].to_vec(),
                mnemonic: InstructionType::In,
                operand_value: None,
            },
            0x0F if opcode_pos + 1 < data.len() && data[opcode_pos + 1] == 0x05 => Instruction {
                offset: pos,
                bytes: data[pos..opcode_pos + 2].to_vec(),
                mnemonic: InstructionType::Syscall,
                operand_value: None,
            },
            _ => {
                let size = if has_rex_w { 2 } else { 1 };
                Instruction {
                    offset: pos,
                    bytes: data[pos..pos + size.min(data.len() - pos)].to_vec(),
                    mnemonic: InstructionType::Other,
                    operand_value: None,
                }
            }
        }
    }

    fn classify_hook_behavior(&self, data: &[u8], blocks: &[BasicBlock]) -> HookBehavior {
        // Check for persistence indicators in surrounding data
        let search_region = data;

        for pattern in PERSISTENCE_INDICATORS {
            if search_region.windows(pattern.len()).any(|w| w == *pattern) {
                return HookBehavior::Persistence;
            }
        }

        for pattern in EXFIL_INDICATORS {
            if search_region.windows(pattern.len()).any(|w| w == *pattern) {
                return HookBehavior::DataExfiltration;
            }
        }

        // Analyze call patterns
        let mut has_call_to_original = false;
        let mut has_additional_calls = false;
        let mut call_count = 0;

        for block in blocks {
            for inst in &block.instructions {
                if inst.mnemonic == InstructionType::Call {
                    call_count += 1;
                    if call_count == 1 {
                        has_call_to_original = true;
                    } else {
                        has_additional_calls = true;
                    }
                }
            }
        }

        if has_call_to_original && !has_additional_calls {
            HookBehavior::Passthrough
        } else if has_call_to_original && has_additional_calls {
            HookBehavior::Interception
        } else if !has_call_to_original && call_count > 0 {
            HookBehavior::CodeInjection
        } else {
            HookBehavior::Unknown
        }
    }

    fn find_hook_targets(&self, data: &[u8]) -> Vec<(usize, Vec<u8>)> {
        let mut targets = Vec::new();

        // Look for BST write patterns that indicate hook installation
        for i in 0..data.len().saturating_sub(16) {
            for pattern in BST_WRITE_PATTERNS {
                if data[i..].starts_with(pattern.bytes) {
                    let region_end = (i + 256).min(data.len());
                    targets.push((i, data[i..region_end].to_vec()));
                    break;
                }
            }
        }

        targets
    }

    fn detect_bst_hooks(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let targets = self.find_hook_targets(data);

        for (offset, region) in &targets {
            let blocks = self.analyze_code_region(region, *offset);
            let behavior = self.classify_hook_behavior(data, &blocks);

            if behavior != HookBehavior::Passthrough {
                findings.push(
                    Finding::new(
                        "symexec",
                        behavior.severity(),
                        &format!(
                            "BST hook behavior: {} at 0x{:08X}",
                            behavior.as_str(),
                            offset
                        ),
                        &format!(
                            "Static analysis of code at offset 0x{:08X} classifies hook \
                             behavior as '{}'. {} basic blocks analyzed, {} instructions decoded.",
                            offset,
                            behavior.as_str(),
                            blocks.len(),
                            blocks.iter().map(|b| b.instructions.len()).sum::<usize>(),
                        ),
                    )
                    .with_confidence(match behavior {
                        HookBehavior::Persistence | HookBehavior::DataExfiltration => 0.85,
                        HookBehavior::Interception | HookBehavior::CodeInjection => 0.75,
                        _ => 0.55,
                    })
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", offset),
                        "behavior": behavior.as_str(),
                        "basic_blocks": blocks.len(),
                        "total_instructions": blocks.iter().map(|b| b.instructions.len()).sum::<usize>(),
                    }))
                    .with_recommendation(match behavior {
                        HookBehavior::Persistence => "Hook writes to non-volatile storage. Firmware reflash required.",
                        HookBehavior::DataExfiltration => "Hook accesses network protocols. Isolate system immediately.",
                        HookBehavior::CodeInjection => "Hook injects code without calling original. Full remediation needed.",
                        HookBehavior::Interception => "Hook intercepts and modifies data flow.",
                        _ => "Further manual analysis recommended.",
                    }),
                );
            }
        }

        findings
    }

    fn detect_suspicious_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for SMM-related patterns (System Management Mode exploitation)
        let smm_patterns: &[&[u8]] = &[
            &[0x0F, 0xAA], // RSM (return from SMM)
            b"SMRAM",
            b"SMM_BASE",
        ];

        for pattern in smm_patterns {
            if let Some(pos) = data.windows(pattern.len()).position(|w| w == *pattern) {
                findings.push(
                    Finding::new(
                        "symexec",
                        Severity::High,
                        &format!("SMM-related code at offset 0x{:08X}", pos),
                        &format!(
                            "Found SMM-related byte pattern at offset 0x{:08X}. \
                             This may indicate System Management Mode exploitation for \
                             persistent, invisible hooks.",
                            pos,
                        ),
                    )
                    .with_confidence(0.65)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", pos),
                        "pattern_length": pattern.len(),
                    })),
                );
            }
        }

        findings
    }

    /// Run the bounded symbolic execution engine over code regions that
    /// contain dangerous sink instructions (WRMSR / port I/O / CPUID) and
    /// report sinks that are reachable under satisfiable path conditions.
    fn detect_symbolic_sinks(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Find candidate sink instructions.
        let mut regions: Vec<usize> = Vec::new();
        for i in 0..data.len().saturating_sub(1) {
            let is_sink = (data[i] == 0x0F && matches!(data[i + 1], 0x30 | 0x32 | 0xA2))
                || matches!(data[i], 0xEC..=0xEF);
            if is_sink {
                regions.push(i);
            }
        }
        if regions.is_empty() {
            return findings;
        }

        let engine = SymEngine::new(SymConfig::default());
        let mut reported: Vec<(usize, SinkKind)> = Vec::new();

        for &sink_off in &regions {
            // Analyze a window ending at the sink: guards usually precede it.
            let window_start = sink_off.saturating_sub(64);
            let window = &data[window_start..(sink_off + 2).min(data.len())];
            let report = engine.execute(window);

            for sink in &report.sinks {
                // Convert the in-window offset to the image offset.
                let image_off = window_start + sink.offset;
                if reported
                    .iter()
                    .any(|(o, k)| *o == image_off && *k == sink.kind)
                {
                    continue;
                }
                // Only report sinks that are actually guarded by symbolic
                // path conditions — unguarded sink bytes in random data are
                // too noisy.
                if sink.conditions.is_empty() {
                    continue;
                }

                let rendered: Vec<String> = sink.conditions.iter().map(|c| c.render()).collect();
                let severity = if matches!(sink.kind, SinkKind::Wrmsr | SinkKind::Cli) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                reported.push((image_off, sink.kind));

                findings.push(
                    Finding::new(
                        "symexec",
                        severity,
                        &format!(
                            "Symbolically reachable {} sink at 0x{:08X}",
                            sink.kind.as_str(),
                            image_off
                        ),
                        &format!(
                            "Bounded symbolic execution found a satisfiable path to a \
                             {} instruction at offset 0x{:08X}, guarded by: {}.",
                            sink.kind.as_str(),
                            image_off,
                            rendered.join(" ∧ ")
                        ),
                    )
                    .with_confidence(0.78)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", image_off),
                        "sink": sink.kind.as_str(),
                        "path_conditions": rendered,
                        "path_length": sink.path_length,
                        "paths_explored": report.paths_explored,
                    }))
                    .with_recommendation(
                        "Disassemble the region around the sink and verify the guard \
                         logic; WRMSR/port sinks in firmware implants often patch MSRs \
                         or reflash SPI flash conditionally.",
                    ),
                );
            }
        }

        findings
    }
}

impl Detector for SymExecDetector {
    fn name(&self) -> &str {
        "symexec"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.detect_bst_hooks(&data));
        findings.extend(self.detect_suspicious_patterns(&data));
        findings.extend(self.detect_symbolic_sinks(&data));

        Ok(findings)
    }
}
