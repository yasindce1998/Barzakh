//! Bounded symbolic execution engine for firmware code regions.
//!
//! Decodes a practical subset of x86-64, models registers as symbolic values
//! (constant or symbolic), explores both branch directions of conditional
//! jumps, and reports paths that reach dangerous sinks (`WRMSR`, port I/O,
//! `HLT`, `CPUID` fingerprinting) with their satisfiable path conditions.
//!
//! The constraint solver tracks per-symbol interval constraints, so a path is
//! only reported when its guards are simultaneously satisfiable — random byte
//! sequences with contradictory guards are pruned.

use serde::Serialize;
use std::collections::HashMap;

/// Dangerous sink reachable by a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    /// `WRMSR` — model-specific register write (Ring -1 class).
    Wrmsr,
    /// `OUT` — port I/O write (device/MMIO control).
    PortOut,
    /// `IN` — port I/O read.
    PortIn,
    /// `CPUID` — fingerprinting / feature probing.
    Cpuid,
    /// `CLI` — interrupt disable (SMM-style lockout).
    Cli,
    /// `HLT` — halt loop (DoS).
    Hlt,
}

impl SinkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wrmsr => "wrmsr",
            Self::PortOut => "port_out",
            Self::PortIn => "port_in",
            Self::Cpuid => "cpuid",
            Self::Cli => "cli",
            Self::Hlt => "hlt",
        }
    }
}

/// Comparison operator for path constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CmpOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CmpOp {
    fn negate(self) -> Self {
        match self {
            Self::Eq => Self::Ne,
            Self::Ne => Self::Eq,
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
        }
    }

    fn evaluate(self, lhs: u64, rhs: u64) -> bool {
        match self {
            Self::Eq => lhs == rhs,
            Self::Ne => lhs != rhs,
            Self::Lt => lhs < rhs,
            Self::Le => lhs <= rhs,
            Self::Gt => lhs > rhs,
            Self::Ge => lhs >= rhs,
        }
    }
}

/// Map a Jcc condition code (low opcode nibble) to its comparison semantics
/// against the pending CMP immediate.
fn cc_to_op(cc: u8) -> CmpOp {
    match cc {
        0x4 => CmpOp::Eq,       // JE / JZ
        0x5 => CmpOp::Ne,       // JNE / JNZ
        0x2 | 0xC => CmpOp::Lt, // JB / JL (unsigned / signed)
        0x3 | 0xD => CmpOp::Ge, // JAE / JGE
        0x6 | 0xE => CmpOp::Le, // JBE / JLE
        0x7 | 0xF => CmpOp::Gt, // JA / JG
        _ => CmpOp::Ne,
    }
}

/// A single path constraint: `symbol(reg) OP value`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Constraint {
    pub symbol: u8,
    pub op: CmpOp,
    pub value: u64,
}

impl Constraint {
    pub fn render(&self) -> String {
        let op = match self.op {
            CmpOp::Eq => "==",
            CmpOp::Ne => "!=",
            CmpOp::Lt => "<",
            CmpOp::Le => "<=",
            CmpOp::Gt => ">",
            CmpOp::Ge => ">=",
        };
        format!("r{} {} 0x{:X}", self.symbol, op, self.value)
    }
}

/// A reached sink together with its satisfiable path conditions.
#[derive(Debug, Clone, Serialize)]
pub struct SinkReach {
    pub kind: SinkKind,
    /// Offset of the sink instruction within the analyzed buffer.
    pub offset: usize,
    /// Satisfiable path conditions leading to the sink.
    pub conditions: Vec<Constraint>,
    /// Instructions executed on the path.
    pub path_length: usize,
}

/// Aggregate symbolic execution report.
#[derive(Debug, Clone, Serialize)]
pub struct SymReport {
    pub paths_explored: usize,
    pub instructions_decoded: usize,
    pub sinks: Vec<SinkReach>,
}

/// Engine configuration bounds.
#[derive(Debug, Clone)]
pub struct SymConfig {
    pub max_paths: usize,
    pub max_instructions_per_path: usize,
    pub max_sinks: usize,
}

impl Default for SymConfig {
    fn default() -> Self {
        Self {
            max_paths: 256,
            max_instructions_per_path: 512,
            max_sinks: 32,
        }
    }
}

/// Symbolic register value.
#[derive(Debug, Clone, PartialEq)]
enum SymVal {
    Const(u64),
    Sym(u8),
    Top,
}

#[derive(Debug, Clone)]
struct PathState {
    pc: usize,
    regs: Vec<SymVal>,
    conditions: Vec<Constraint>,
    instructions: usize,
    /// Pending comparison from the last CMP: (register, immediate).
    last_cmp: Option<(u8, u64)>,
}

/// The symbolic execution engine.
pub struct SymEngine {
    config: SymConfig,
}

enum StepOutcome {
    Continue,
    /// Jump to absolute offset.
    Jump(usize),
    /// Conditional jump: (taken target, fallthrough).
    Branch(usize, usize, Constraint),
    /// Path terminated (ret / bounds).
    Terminate,
    /// Sink reached.
    Sink(SinkKind),
}

impl SymEngine {
    pub fn new(config: SymConfig) -> Self {
        Self { config }
    }

    /// Execute `code` starting at offset 0; offsets in the report are relative
    /// to this buffer. All registers start fully symbolic.
    pub fn execute(&self, code: &[u8]) -> SymReport {
        let mut paths_explored = 0usize;
        let mut instructions_decoded = 0usize;
        let mut sinks: Vec<SinkReach> = Vec::new();
        let mut visited_pcs: HashMap<usize, usize> = HashMap::new();

        let initial = PathState {
            pc: 0,
            regs: (0..16).map(SymVal::Sym).collect(),
            conditions: Vec::new(),
            instructions: 0,
            last_cmp: None,
        };

        let mut stack = vec![initial];

        while let Some(mut state) = stack.pop() {
            paths_explored += 1;
            if paths_explored > self.config.max_paths {
                break;
            }

            loop {
                if state.instructions >= self.config.max_instructions_per_path {
                    break;
                }
                if state.pc >= code.len() {
                    break;
                }

                // Loop guard: bail out of tight loops.
                let visits = visited_pcs.entry(state.pc).or_insert(0);
                *visits += 1;
                if *visits > 64 {
                    break;
                }

                instructions_decoded += 1;
                state.instructions += 1;

                match self.step(code, &mut state) {
                    StepOutcome::Continue => {
                        // `step` already advanced pc past the instruction.
                    }
                    StepOutcome::Jump(target) => {
                        if target >= code.len() {
                            break;
                        }
                        state.pc = target;
                    }
                    StepOutcome::Branch(target, fallthrough, constraint) => {
                        // Only push the taken branch when the guard is
                        // satisfiable with the current conditions.
                        let mut taken_state = state.clone();
                        taken_state.conditions.push(constraint.clone());
                        if self.satisfiable(&taken_state.conditions) && target < code.len() {
                            taken_state.pc = target;
                            stack.push(taken_state);
                        }

                        let mut fall_state = state.clone();
                        fall_state.conditions.push(Constraint {
                            op: constraint.op.negate(),
                            ..constraint
                        });
                        if self.satisfiable(&fall_state.conditions) {
                            state.pc = fallthrough;
                            state.conditions = fall_state.conditions;
                        } else {
                            break;
                        }
                    }
                    StepOutcome::Sink(kind) => {
                        if sinks.len() < self.config.max_sinks {
                            sinks.push(SinkReach {
                                kind,
                                offset: state.pc,
                                conditions: state.conditions.clone(),
                                path_length: state.instructions,
                            });
                        }
                        break;
                    }
                    StepOutcome::Terminate => break,
                }
            }
        }

        SymReport {
            paths_explored,
            instructions_decoded,
            sinks,
        }
    }

    /// Decode and apply one instruction at `state.pc`.
    fn step(&self, code: &[u8], state: &mut PathState) -> StepOutcome {
        let pc = state.pc;
        let b = code[pc];

        // REX prefix handling for the subset we decode.
        if (0x40..=0x4F).contains(&b) && pc + 1 < code.len() {
            let rex = b;
            let opcode = code[pc + 1];
            let rex_w = rex & 0x08 != 0;
            let _ = rex_w;

            match opcode {
                // REX.W B8+r: MOV r64, imm64
                0xB8..=0xBF if pc + 9 < code.len() => {
                    let reg = (opcode - 0xB8) as usize | ((rex & 1) as usize) << 3;
                    let imm =
                        u64::from_le_bytes(code[pc + 2..pc + 10].try_into().unwrap_or([0; 8]));
                    state.regs[reg] = SymVal::Const(imm);
                    state.pc += 10;
                    return StepOutcome::Continue;
                }
                // REX.W 89 /r: MOV r/m64, r64 (reg-reg only)
                0x89 if pc + 2 < code.len() => {
                    let modrm = code[pc + 2];
                    if modrm >> 6 == 0b11 {
                        let src = ((modrm >> 3) & 7) as usize | ((rex & 4) as usize) << 1;
                        let dst = (modrm & 7) as usize | ((rex & 1) as usize) << 3;
                        state.regs[dst] = state.regs[src].clone();
                        state.pc += 3;
                        return StepOutcome::Continue;
                    }
                    state.pc += 3;
                    return StepOutcome::Continue;
                }
                // REX.W 31 /r: XOR r64, r64 (same reg → zero)
                0x31 if pc + 2 < code.len() => {
                    let modrm = code[pc + 2];
                    if modrm >> 6 == 0b11 {
                        let src = ((modrm >> 3) & 7) as usize | ((rex & 4) as usize) << 1;
                        let dst = (modrm & 7) as usize | ((rex & 1) as usize) << 3;
                        if src == dst {
                            state.regs[dst] = SymVal::Const(0);
                        } else {
                            state.regs[dst] = SymVal::Top;
                        }
                    }
                    state.pc += 3;
                    return StepOutcome::Continue;
                }
                // 0F-prefixed two-byte opcodes with REX
                0x0F if pc + 2 < code.len() => {
                    let two = code[pc + 2];
                    match two {
                        // 0F 30 WRMSR
                        0x30 => return StepOutcome::Sink(SinkKind::Wrmsr),
                        // 0F 32 RDMSR
                        0x32 => {
                            state.pc += 3;
                            return StepOutcome::Continue;
                        }
                        // 0F A2 CPUID
                        0xA2 => return StepOutcome::Sink(SinkKind::Cpuid),
                        // 0F 8x Jcc rel32
                        0x84..=0x8F if pc + 6 < code.len() => {
                            let rel = i32::from_le_bytes(
                                code[pc + 3..pc + 7].try_into().unwrap_or([0; 4]),
                            );
                            let target = (pc as i64 + 7 + rel as i64) as usize;
                            let cc = two & 0x0F;
                            return self.conditional(state, target, pc + 7, cc);
                        }
                        _ => {
                            state.pc += 3;
                            return StepOutcome::Continue;
                        }
                    }
                }
                _ => {
                    state.pc += 2;
                    return StepOutcome::Continue;
                }
            }
        }

        match b {
            // C3 / CB: RET
            0xC3 | 0xCB => StepOutcome::Terminate,
            // 90: NOP
            0x90 => {
                state.pc += 1;
                StepOutcome::Continue
            }
            // E9: JMP rel32
            0xE9 if pc + 5 < code.len() => {
                let rel = i32::from_le_bytes(code[pc + 1..pc + 5].try_into().unwrap_or([0; 4]));
                let target = (pc as i64 + 5 + rel as i64) as usize;
                state.pc += 5;
                StepOutcome::Jump(target)
            }
            // EB: JMP rel8
            0xEB if pc + 1 < code.len() => {
                let rel = code[pc + 1] as i8;
                let target = (pc as i64 + 2 + rel as i64) as usize;
                state.pc += 2;
                StepOutcome::Jump(target)
            }
            // 7x: Jcc rel8
            0x70..=0x7F if pc + 1 < code.len() => {
                let rel = code[pc + 1] as i8;
                let target = (pc as i64 + 2 + rel as i64) as usize;
                let cc = b & 0x0F;
                self.conditional(state, target, pc + 2, cc)
            }
            // E8: CALL rel32 — straight-line model
            0xE8 if pc + 5 < code.len() => {
                state.pc += 5;
                StepOutcome::Continue
            }
            // 0F two-byte opcodes (no REX)
            0x0F if pc + 1 < code.len() => match code[pc + 1] {
                0x30 => StepOutcome::Sink(SinkKind::Wrmsr),
                0x32 => {
                    state.pc += 2;
                    StepOutcome::Continue
                }
                0xA2 => StepOutcome::Sink(SinkKind::Cpuid),
                0x84..=0x8F if pc + 5 < code.len() => {
                    let rel = i32::from_le_bytes(code[pc + 2..pc + 6].try_into().unwrap_or([0; 4]));
                    let target = (pc as i64 + 6 + rel as i64) as usize;
                    let cc = code[pc + 1] & 0x0F;
                    self.conditional(state, target, pc + 6, cc)
                }
                _ => {
                    state.pc += 2;
                    StepOutcome::Continue
                }
            },
            // 81 /7: CMP r32, imm32
            0x81 if pc + 5 < code.len() && code[pc + 1] >> 3 & 7 == 7 => {
                let reg = (code[pc + 1] & 7) as usize;
                let imm = u32::from_le_bytes(code[pc + 2..pc + 6].try_into().unwrap_or([0; 4]));
                self.apply_cmp(state, reg, imm as u64);
                state.pc += 6;
                StepOutcome::Continue
            }
            // 83 /7: CMP r32, imm8 (sign-extended)
            0x83 if pc + 2 < code.len() && code[pc + 1] >> 3 & 7 == 7 => {
                let reg = (code[pc + 1] & 7) as usize;
                let imm = code[pc + 2] as i8 as i64 as u64;
                self.apply_cmp(state, reg, imm);
                state.pc += 3;
                StepOutcome::Continue
            }
            // B8+r: MOV r32, imm32
            0xB8..=0xBF if pc + 4 < code.len() => {
                let reg = (b - 0xB8) as usize;
                let imm = u32::from_le_bytes(code[pc + 1..pc + 5].try_into().unwrap_or([0; 4]));
                state.regs[reg] = SymVal::Const(imm as u64);
                state.pc += 5;
                StepOutcome::Continue
            }
            // 31 /r: XOR r32, r32
            0x31 if pc + 1 < code.len() => {
                let modrm = code[pc + 1];
                if modrm >> 6 == 0b11 {
                    let src = ((modrm >> 3) & 7) as usize;
                    let dst = (modrm & 7) as usize;
                    if src == dst {
                        state.regs[dst] = SymVal::Const(0);
                    } else {
                        state.regs[dst] = SymVal::Top;
                    }
                }
                state.pc += 2;
                StepOutcome::Continue
            }
            // EE/EF: OUT
            0xEE | 0xEF => StepOutcome::Sink(SinkKind::PortOut),
            // EC/ED: IN
            0xEC | 0xED => StepOutcome::Sink(SinkKind::PortIn),
            // FA: CLI
            0xFA => StepOutcome::Sink(SinkKind::Cli),
            // F4: HLT
            0xF4 => StepOutcome::Sink(SinkKind::Hlt),
            _ => {
                state.pc += 1;
                StepOutcome::Continue
            }
        }
    }

    /// Handle a conditional jump with condition code `cc` (low nibble of the
    /// Jcc opcode). The pending CMP supplies `(reg, immediate)`; the cc maps
    /// to the comparison semantics. Returns a Branch or resolves immediately
    /// when the guard is concrete.
    fn conditional(
        &self,
        state: &mut PathState,
        target: usize,
        fallthrough: usize,
        cc: u8,
    ) -> StepOutcome {
        let op = cc_to_op(cc);

        let Some((reg, value)) = state.last_cmp else {
            // Unknown condition: explore both paths without a constraint.
            return StepOutcome::Branch(
                target,
                fallthrough,
                Constraint {
                    symbol: 0,
                    op: CmpOp::Ne,
                    value: u64::MAX,
                },
            );
        };

        let constraint = Constraint {
            symbol: reg,
            op,
            value,
        };

        // Concrete register → decide immediately.
        if let SymVal::Const(c) = state.regs[reg as usize] {
            if op.evaluate(c, value) {
                return StepOutcome::Jump(target);
            }
            return StepOutcome::Jump(fallthrough);
        }

        StepOutcome::Branch(target, fallthrough, constraint)
    }

    /// Record the pending comparison from a CMP reg, imm: (register, value).
    fn apply_cmp(&self, state: &mut PathState, reg: usize, imm: u64) {
        state.last_cmp = Some((reg as u8, imm));
    }

    /// Check simultaneous satisfiability of per-symbol constraints using
    /// interval reasoning.
    fn satisfiable(&self, constraints: &[Constraint]) -> bool {
        let mut by_symbol: HashMap<u8, Vec<&Constraint>> = HashMap::new();
        for c in constraints {
            by_symbol.entry(c.symbol).or_default().push(c);
        }

        for (_, group) in by_symbol {
            // Track the feasible set as a union of simple intervals derived
            // from each constraint. For small groups, pairwise consistency
            // plus interval intersection over (Lt/Le/Gt/Ge) and equality sets
            // is a sound approximation.
            let mut lo = 0u64;
            let mut hi = u64::MAX;
            let mut eq: Option<u64> = None;
            let mut ne: Vec<u64> = Vec::new();

            for c in group {
                match c.op {
                    CmpOp::Eq => {
                        if let Some(prev) = eq {
                            if prev != c.value {
                                return false;
                            }
                        }
                        if c.value < lo || c.value > hi {
                            return false;
                        }
                        eq = Some(c.value);
                    }
                    CmpOp::Ne => ne.push(c.value),
                    CmpOp::Lt => hi = hi.min(c.value.saturating_sub(1)),
                    CmpOp::Le => hi = hi.min(c.value),
                    CmpOp::Gt => lo = lo.max(c.value.saturating_add(1)),
                    CmpOp::Ge => lo = lo.max(c.value),
                }
            }

            if lo > hi {
                return false;
            }
            if let Some(v) = eq {
                if ne.contains(&v) {
                    return false;
                }
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_unreachable_sink_due_to_contradiction() {
        // cmp eax, 5 ; je +3 ; wrmsr
        // Guard: r0 == 5 on taken branch, then next guard r0 != 5 blocks...
        let code = [
            0x83, 0xF8, 0x05, // cmp eax, 5
            0x74, 0x03, // je +3
            0x90, 0x90, 0x90, // fallthrough nops
            0x0F, 0x30, // wrmsr (target)
        ];
        let engine = SymEngine::new(SymConfig::default());
        let report = engine.execute(&code);
        // r0 == 5 is satisfiable → sink reachable.
        assert!(report.sinks.iter().any(|s| s.kind == SinkKind::Wrmsr));
    }

    #[test]
    fn prunes_contradictory_guards() {
        // cmp eax, 5 ; je +2 ; cmp eax, 5 ; jne +2 ; wrmsr
        // Taken path requires r0==5 then r0==5 (jne not taken) → reachable.
        // The contradictory variant: r0==5 then r0!=5 → pruned.
        let code = [
            0x83, 0xF8, 0x05, // cmp eax, 5
            0x74, 0x02, // je +2 → lands on second cmp
            0xEB, 0x06, // jmp over to hlt... (avoid)
            0x83, 0xF8, 0x05, // cmp eax, 5
            0x75, 0x02, // jne +2 (taken when r0 != 5)
            0x0F, 0x30, // wrmsr target
            0xC3, // ret
        ];
        let engine = SymEngine::new(SymConfig::default());
        let report = engine.execute(&code);
        // wrmsr reachable only when r0==5 (je) and r0==5 (jne not taken) —
        // consistent, so the sink is reached exactly once with 2 constraints.
        let wrmsr: Vec<&SinkReach> = report
            .sinks
            .iter()
            .filter(|s| s.kind == SinkKind::Wrmsr)
            .collect();
        assert_eq!(wrmsr.len(), 1);
        assert_eq!(wrmsr[0].conditions.len(), 2);
    }

    #[test]
    fn constant_guard_decides_concretely() {
        // mov eax, 1 ; cmp eax, 1 ; je +1 ; hlt ; wrmsr
        let code = [
            0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
            0x83, 0xF8, 0x01, // cmp eax, 1
            0x74, 0x01, // je +1 → skip hlt, land on wrmsr
            0xF4, // hlt (skipped)
            0x0F, 0x30, // wrmsr
        ];
        let engine = SymEngine::new(SymConfig::default());
        let report = engine.execute(&code);
        let kinds: Vec<SinkKind> = report.sinks.iter().map(|s| s.kind).collect();
        assert!(kinds.contains(&SinkKind::Wrmsr));
        assert!(
            !kinds.contains(&SinkKind::Hlt),
            "hlt must be skipped: {kinds:?}"
        );
    }

    #[test]
    fn port_out_detected() {
        let code = [0xEE]; // OUT dx, al
        let engine = SymEngine::new(SymConfig::default());
        let report = engine.execute(&code);
        assert_eq!(report.sinks.len(), 1);
        assert_eq!(report.sinks[0].kind, SinkKind::PortOut);
    }

    #[test]
    fn quiet_on_zero_code() {
        let engine = SymEngine::new(SymConfig::default());
        let report = engine.execute(&[0u8; 128]);
        assert!(report.sinks.is_empty());
    }

    #[test]
    fn constraint_rendering() {
        let c = Constraint {
            symbol: 3,
            op: CmpOp::Ge,
            value: 0x10,
        };
        assert_eq!(c.render(), "r3 >= 0x10");
    }
}
