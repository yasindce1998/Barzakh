//! A pragmatic YARA-subset rule engine.
//!
//! Supported rule syntax (sufficient for real-world firmware IOC rules):
//!
//! ```text
//! import "pe"
//!
//! rule BlackLotus_MOK : bootkit uefi {
//!   meta:
//!     family = "BlackLotus"
//!     cve = "CVE-2023-24932"
//!   strings:
//!     $a = "MokManagerTUI" ascii
//!     $b = { 4D 6F 6B ?? 61 6E
//!            DE AD [4-8] BE EF }
//!     $c = /\\SystemRoot\\SystemRoot\\[a-z]{4,8}\.sys/ nocase
//!   condition:
//!     filesize < 500KB and
//!     2 of them and
//!     pe.is_pe and
//!     pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION
//! }
//! ```
//!
//! String kinds: quoted text, hex (with `??` wildcards and `[n-m]` jumps)
//! and `/regex/`, each with `ascii`, `wide`, `nocase` and `fullword`
//! modifiers. Conditions are full boolean expressions with integer
//! arithmetic and bitwise operators, comparisons (`== != < > <= >=`),
//! string operators (`contains`, `startswith`, `endswith`, `matches`),
//! occurrence counts (`#a`), `filesize`, a `pe` module subset, and
//! caller-provided external variables. `any/all/N of them` forms are
//! supported. Sections may span multiple lines.

use std::collections::HashMap;
use std::path::Path;

use aho_corasick::AhoCorasick;
use anyhow::Context;

use barzakh_core::{Detector, DetectorError, Finding, Severity};

// ─── Hex pattern segments ────────────────────────────────────────────

/// One fixed-length segment of a pattern (a run of literal/wildcard bytes
/// between jumps).
#[derive(Debug, Clone, Default)]
pub struct Segment {
    pub bytes: Vec<u8>,
    /// Wildcard mask: `Some(())` = any byte accepted at this position.
    pub mask: Vec<Option<()>>,
}

// ─── Rule strings ────────────────────────────────────────────────────

/// One precomputed searchable encoding of a text string (ascii and/or
/// wide, case-folded when `nocase`).
#[derive(Debug, Clone)]
struct TextVariant {
    bytes: Vec<u8>,
    nocase: bool,
    fullword: bool,
}

#[derive(Debug, Clone)]
enum StrKind {
    Text {
        variants: Vec<TextVariant>,
    },
    Hex {
        segments: Vec<Segment>,
        gaps: Vec<(usize, usize)>,
    },
    Regex {
        regex: regex::bytes::Regex,
        wide: bool,
    },
}

/// A string atom inside a rule.
#[derive(Debug, Clone)]
pub struct RuleString {
    pub identifier: String,
    kind: StrKind,
}

impl RuleString {
    /// The literal bytes when this string is a single plain ascii text
    /// (no wide/nocase/fullword) — used for Aho-Corasick pre-filtering.
    fn plain_bytes(&self) -> Option<&[u8]> {
        match &self.kind {
            StrKind::Text { variants } => {
                if variants.len() == 1
                    && !variants[0].nocase
                    && !variants[0].fullword
                    && variants[0].bytes.iter().all(|b| *b != 0)
                {
                    Some(&variants[0].bytes)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Number of (non-overlapping) matches in `data`; stops early once
    /// `limit` is reached.
    fn count_matches(&self, data: &[u8], limit: usize) -> usize {
        match &self.kind {
            StrKind::Text { variants } => {
                let mut total = 0;
                for variant in variants {
                    if variant.bytes.is_empty() || data.len() < variant.bytes.len() {
                        continue;
                    }
                    let mut p = 0;
                    while p + variant.bytes.len() <= data.len() {
                        if text_variant_matches_at(variant, data, p) {
                            total += 1;
                            if total >= limit {
                                return total;
                            }
                            p += variant.bytes.len();
                        } else {
                            p += 1;
                        }
                    }
                }
                total
            }
            StrKind::Hex { .. } => {
                let mut total = 0;
                if let Some(first) = hex_first_segment(self) {
                    for start in 0..=data.len().saturating_sub(first.bytes.len()) {
                        if segment_matches_at(first, data, start)
                            && segments_match_from(self, data, start + first.bytes.len(), 0)
                        {
                            total += 1;
                            if total >= limit {
                                return total;
                            }
                        }
                    }
                }
                total
            }
            StrKind::Regex { regex, wide } => {
                let mut total = regex.find_iter(data).count();
                if *wide {
                    for run in wide_runs(data) {
                        total += regex.find_iter(&run).count();
                    }
                }
                total.min(limit)
            }
        }
    }
}

/// Decode runs of UTF-16LE-encoded ASCII out of raw data (for `wide`
/// regex matching): consecutive `(byte, 0)` pairs.
fn wide_runs(data: &[u8]) -> Vec<Vec<u8>> {
    let mut runs = Vec::new();
    for alignment in 0..2 {
        let mut current: Vec<u8> = Vec::new();
        let mut i = alignment;
        while i + 1 < data.len() {
            if data[i] != 0 && data[i + 1] == 0 {
                current.push(data[i]);
                i += 2;
            } else {
                if current.len() >= 4 {
                    runs.push(std::mem::take(&mut current));
                } else {
                    current.clear();
                }
                i += 1;
            }
        }
        if current.len() >= 4 {
            runs.push(current);
        }
    }
    runs
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn text_variant_matches_at(variant: &TextVariant, data: &[u8], p: usize) -> bool {
    let len = variant.bytes.len();
    if p + len > data.len() {
        return false;
    }
    for (i, &pb) in variant.bytes.iter().enumerate() {
        let db = data[p + i];
        let equal = if variant.nocase {
            pb.eq_ignore_ascii_case(&db)
        } else {
            pb == db
        };
        if !equal {
            return false;
        }
    }
    if variant.fullword {
        let before_ok = p == 0 || !is_word_byte(data[p - 1]);
        let after_ok = p + len >= data.len() || !is_word_byte(data[p + len]);
        if !before_ok || !after_ok {
            return false;
        }
    }
    true
}

// ─── Values and expressions ──────────────────────────────────────────

/// A runtime value in a condition expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Bool(bool),
    Str(String),
}

impl Value {
    fn truthy(&self) -> bool {
        match self {
            Value::Bool(b) => *b,
            Value::Int(n) => *n != 0,
            Value::Str(s) => !s.is_empty(),
        }
    }

    fn as_int(&self) -> i64 {
        match self {
            Value::Int(n) => *n,
            Value::Bool(b) => i64::from(*b),
            Value::Str(_) => 0,
        }
    }
}

/// Caller-provided external variable (referenced by name in conditions).
#[derive(Debug, Clone, PartialEq)]
pub enum ExternalValue {
    Bool(bool),
    Int(i64),
    Str(String),
}

/// External variables visible to rule conditions.
pub type ExternalVars = HashMap<String, ExternalValue>;

/// Fields of the `pe` module subset.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PeField {
    IsPe,
    Machine,
    Subsystem,
    NumberOfSections,
    Timestamp,
    EntryPoint,
    Characteristics,
}

/// `pe.MACHINE_*` / `pe.SUBSYSTEM_*` / characteristic constants.
fn pe_constant(name: &str) -> Option<i64> {
    Some(match name {
        "MACHINE_I386" => 0x014c,
        "MACHINE_AMD64" => 0x8664,
        "MACHINE_ARM" => 0x01c0,
        "MACHINE_ARM64" => 0xaa64,
        "MACHINE_IA64" => 0x0200,
        "SUBSYSTEM_NATIVE" => 1,
        "SUBSYSTEM_WINDOWS_GUI" => 2,
        "SUBSYSTEM_WINDOWS_CUI" => 3,
        "SUBSYSTEM_EFI_APPLICATION" => 10,
        "SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER" => 11,
        "SUBSYSTEM_EFI_RUNTIME_DRIVER" => 12,
        "SUBSYSTEM_EFI_ROM" => 13,
        "DLL" => 0x2000,
        "EXECUTABLE_IMAGE" => 0x0002,
        _ => return None,
    })
}

fn pe_field_by_name(name: &str) -> Option<PeField> {
    Some(match name {
        "is_pe" => PeField::IsPe,
        "machine" => PeField::Machine,
        "subsystem" => PeField::Subsystem,
        "number_of_sections" => PeField::NumberOfSections,
        "timestamp" => PeField::Timestamp,
        "entry_point" => PeField::EntryPoint,
        "characteristics" => PeField::Characteristics,
        _ => return None,
    })
}

fn pe_field_name(field: PeField) -> &'static str {
    match field {
        PeField::IsPe => "pe.is_pe",
        PeField::Machine => "pe.machine",
        PeField::Subsystem => "pe.subsystem",
        PeField::NumberOfSections => "pe.number_of_sections",
        PeField::Timestamp => "pe.timestamp",
        PeField::EntryPoint => "pe.entry_point",
        PeField::Characteristics => "pe.characteristics",
    }
}

/// Binary operators (logical, comparison, string, arithmetic, bitwise).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
    BitAnd,
    BitOr,
    BitXor,
}

/// A parsed condition expression.
#[derive(Debug, Clone)]
pub enum Expr {
    Lit(Value),
    /// `$a` — did the string match at all.
    StrRef(String),
    /// `#a` — number of matches.
    CountRef(String),
    /// `filesize` in bytes.
    Filesize,
    /// External variable by name.
    External(String),
    PeField(PeField),
    /// `pe.sections[n].name`
    PeSectionName(usize),
    Not(Box<Expr>),
    Neg(Box<Expr>),
    Binary(BinOp, Box<Expr>, Box<Expr>),
    /// `N of them` — at least N declared strings matched.
    NOfThem(Vec<String>, usize),
}

impl Expr {
    /// Collect referenced string identifiers (`$a`, `#a` — counts refer
    /// to the same declarations, so `#a` validates against `$a`).
    fn string_refs(&self, out: &mut Vec<String>) {
        match self {
            Expr::StrRef(id) => out.push(id.clone()),
            Expr::CountRef(id) => out.push(id.replacen('#', "$", 1)),
            Expr::Not(inner) | Expr::Neg(inner) => inner.string_refs(out),
            Expr::Binary(_, a, b) => {
                a.string_refs(out);
                b.string_refs(out);
            }
            Expr::NOfThem(ids, _) => out.extend(ids.iter().cloned()),
            _ => {}
        }
    }

    fn render(&self) -> String {
        match self {
            Expr::Lit(v) => match v {
                Value::Int(n) => n.to_string(),
                Value::Bool(b) => b.to_string(),
                Value::Str(s) => format!("{s:?}"),
            },
            Expr::StrRef(id) => id.clone(),
            Expr::CountRef(id) => id.clone(),
            Expr::Filesize => "filesize".to_string(),
            Expr::External(name) => name.clone(),
            Expr::PeField(f) => pe_field_name(*f).to_string(),
            Expr::PeSectionName(n) => format!("pe.sections[{n}].name"),
            Expr::Not(inner) => format!("not {}", inner.render()),
            Expr::Neg(inner) => format!("-{}", inner.render()),
            Expr::Binary(op, a, b) => {
                format!("({} {} {})", a.render(), binop_text(*op), b.render())
            }
            Expr::NOfThem(_, n) => format!("{n} of them"),
        }
    }

    fn eval(&self, ctx: &RuleEval<'_>) -> Value {
        match self {
            Expr::Lit(v) => v.clone(),
            Expr::StrRef(id) => Value::Bool(ctx.matched_of(id)),
            Expr::CountRef(id) => Value::Int(ctx.count_of(id)),
            Expr::Filesize => Value::Int(ctx.state.filesize as i64),
            Expr::External(name) => ctx
                .state
                .externals
                .get(name)
                .map(|v| match v {
                    ExternalValue::Bool(b) => Value::Bool(*b),
                    ExternalValue::Int(n) => Value::Int(*n),
                    ExternalValue::Str(s) => Value::Str(s.clone()),
                })
                .unwrap_or(Value::Bool(false)),
            Expr::PeField(field) => ctx.state.pe.field(*field),
            Expr::PeSectionName(n) => Value::Str(
                ctx.state
                    .pe
                    .section_names
                    .get(*n)
                    .cloned()
                    .unwrap_or_default(),
            ),
            Expr::Not(inner) => Value::Bool(!inner.eval(ctx).truthy()),
            Expr::Neg(inner) => Value::Int(-inner.eval(ctx).as_int()),
            Expr::Binary(op, a, b) => eval_binary(*op, a, b, ctx),
            Expr::NOfThem(ids, n) => {
                let matched = ids.iter().filter(|id| ctx.matched_of(id)).count();
                Value::Bool(matched >= *n)
            }
        }
    }
}

fn binop_text(op: BinOp) -> &'static str {
    match op {
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Gt => ">",
        BinOp::Le => "<=",
        BinOp::Ge => ">=",
        BinOp::Contains => "contains",
        BinOp::StartsWith => "startswith",
        BinOp::EndsWith => "endswith",
        BinOp::Matches => "matches",
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Mod => "%",
        BinOp::BitAnd => "&",
        BinOp::BitOr => "|",
        BinOp::BitXor => "^",
    }
}

fn eval_binary(op: BinOp, a: &Expr, b: &Expr, ctx: &RuleEval<'_>) -> Value {
    match op {
        BinOp::And => {
            if !a.eval(ctx).truthy() {
                return Value::Bool(false);
            }
            Value::Bool(b.eval(ctx).truthy())
        }
        BinOp::Or => {
            if a.eval(ctx).truthy() {
                return Value::Bool(true);
            }
            Value::Bool(b.eval(ctx).truthy())
        }
        BinOp::Add
        | BinOp::Sub
        | BinOp::Mul
        | BinOp::Div
        | BinOp::Mod
        | BinOp::BitAnd
        | BinOp::BitOr
        | BinOp::BitXor => {
            let (x, y) = (a.eval(ctx).as_int(), b.eval(ctx).as_int());
            let out = match op {
                BinOp::Add => x.wrapping_add(y),
                BinOp::Sub => x.wrapping_sub(y),
                BinOp::Mul => x.wrapping_mul(y),
                BinOp::Div => {
                    if y == 0 {
                        0
                    } else {
                        x.wrapping_div(y)
                    }
                }
                BinOp::Mod => {
                    if y == 0 {
                        0
                    } else {
                        x.wrapping_rem(y)
                    }
                }
                BinOp::BitAnd => x & y,
                BinOp::BitOr => x | y,
                BinOp::BitXor => x ^ y,
                _ => unreachable!(),
            };
            Value::Int(out)
        }
        BinOp::Eq | BinOp::Ne => {
            let (va, vb) = (a.eval(ctx), b.eval(ctx));
            let equal = match (&va, &vb) {
                (Value::Int(x), Value::Int(y)) => x == y,
                (Value::Bool(x), Value::Bool(y)) => x == y,
                (Value::Str(x), Value::Str(y)) => x == y,
                (Value::Int(x), Value::Bool(y)) => (*x != 0) == *y,
                (Value::Bool(x), Value::Int(y)) => *x == (*y != 0),
                _ => false,
            };
            Value::Bool(if op == BinOp::Eq { equal } else { !equal })
        }
        BinOp::Lt | BinOp::Gt | BinOp::Le | BinOp::Ge => {
            let (x, y) = (a.eval(ctx).as_int(), b.eval(ctx).as_int());
            Value::Bool(match op {
                BinOp::Lt => x < y,
                BinOp::Gt => x > y,
                BinOp::Le => x <= y,
                BinOp::Ge => x >= y,
                _ => unreachable!(),
            })
        }
        BinOp::Contains | BinOp::StartsWith | BinOp::EndsWith => {
            let (va, vb) = (a.eval(ctx), b.eval(ctx));
            let (Value::Str(x), Value::Str(y)) = (&va, &vb) else {
                return Value::Bool(false);
            };
            Value::Bool(match op {
                BinOp::Contains => x.contains(y.as_str()),
                BinOp::StartsWith => x.starts_with(y.as_str()),
                BinOp::EndsWith => x.ends_with(y.as_str()),
                _ => unreachable!(),
            })
        }
        BinOp::Matches => {
            let (va, vb) = (a.eval(ctx), b.eval(ctx));
            let (Value::Str(x), Value::Str(y)) = (&va, &vb) else {
                return Value::Bool(false);
            };
            Value::Bool(regex::Regex::new(y).is_ok_and(|re| re.is_match(x)))
        }
    }
}

// ─── PE parsing (module subset) ──────────────────────────────────────

/// Parsed PE header facts exposed to conditions.
#[derive(Debug, Clone, Default)]
pub struct PeInfo {
    pub is_pe: bool,
    pub machine: i64,
    pub number_of_sections: i64,
    pub timestamp: i64,
    pub entry_point: i64,
    pub characteristics: i64,
    pub subsystem: i64,
    pub section_names: Vec<String>,
}

impl PeInfo {
    fn field(&self, field: PeField) -> Value {
        match field {
            PeField::IsPe => Value::Bool(self.is_pe),
            PeField::Machine => Value::Int(self.machine),
            PeField::Subsystem => Value::Int(self.subsystem),
            PeField::NumberOfSections => Value::Int(self.number_of_sections),
            PeField::Timestamp => Value::Int(self.timestamp),
            PeField::EntryPoint => Value::Int(self.entry_point),
            PeField::Characteristics => Value::Int(self.characteristics),
        }
    }
}

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *data.get(at)?,
        *data.get(at + 1)?,
        *data.get(at + 2)?,
        *data.get(at + 3)?,
    ]))
}

/// Parse the PE facts used by the `pe` module subset. Non-PE data yields
/// `is_pe: false` with zeroed fields.
pub fn parse_pe(data: &[u8]) -> PeInfo {
    let mut info = PeInfo::default();
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return info;
    }
    let Some(e_lfanew) = le_u32(data, 0x3c).map(|v| v as usize) else {
        return info;
    };
    if e_lfanew < 4 || e_lfanew + 24 > data.len() {
        return info;
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return info;
    }
    let coff = e_lfanew + 4;
    info.is_pe = true;
    info.machine = le_u16(data, coff).unwrap_or(0) as i64;
    info.number_of_sections = le_u16(data, coff + 2).unwrap_or(0) as i64;
    info.timestamp = le_u32(data, coff + 8).unwrap_or(0) as i64;
    let size_optional = le_u16(data, coff + 16).unwrap_or(0) as usize;
    info.characteristics = le_u16(data, coff + 18).unwrap_or(0) as i64;

    let opt = coff + 20;
    if size_optional >= 70 && opt + 70 <= data.len() {
        info.entry_point = le_u32(data, opt + 16).unwrap_or(0) as i64;
        info.subsystem = le_u16(data, opt + 68).unwrap_or(0) as i64;
        let table = opt + size_optional;
        for i in 0..info.number_of_sections.min(96) {
            let off = table + (i as usize) * 40;
            if off + 40 > data.len() {
                break;
            }
            let name = &data[off..off + 8];
            let end = name.iter().position(|&b| b == 0).unwrap_or(8);
            info.section_names
                .push(String::from_utf8_lossy(&name[..end]).to_string());
        }
    }
    info
}

// ─── Condition tokenizer / parser ────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    StrRef(String),
    CountRef(String),
    Int(i64),
    Str(String),
    /// `/regex/` literal (only valid after the `matches` operator).
    Regex(String),
    Op(String),
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
}

fn tokenize_condition(text: &str) -> anyhow::Result<Vec<Tok>> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c == '$' || c == '#' {
            let mut name = String::new();
            i += 1;
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                name.push(chars[i]);
                i += 1;
            }
            if name.is_empty() {
                anyhow::bail!("empty string reference in condition");
            }
            tokens.push(if c == '$' {
                Tok::StrRef(name)
            } else {
                Tok::CountRef(name)
            });
            continue;
        }
        if c == '/' && matches!(tokens.last(), Some(Tok::Ident(k)) if k == "matches") {
            // Regex literal after `matches`: read until the unescaped
            // closing slash (`\/` is a literal slash).
            i += 1;
            let mut pattern = String::new();
            while i < chars.len() && chars[i] != '/' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    if chars[i + 1] == '/' {
                        i += 1;
                        pattern.push('/');
                        i += 1;
                        continue;
                    }
                    pattern.push(chars[i]);
                    i += 1;
                }
                pattern.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                anyhow::bail!("unterminated regex literal in condition");
            }
            i += 1; // closing slash
            tokens.push(Tok::Regex(pattern));
            continue;
        }
        if c == '"' {
            i += 1;
            let mut s = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    match chars[i] {
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        other => s.push(other),
                    }
                } else {
                    s.push(chars[i]);
                }
                i += 1;
            }
            if i >= chars.len() {
                anyhow::bail!("unterminated string literal in condition");
            }
            i += 1; // closing quote
            tokens.push(Tok::Str(s));
            continue;
        }
        if c.is_ascii_digit() {
            let start = i;
            if c == '0' && i + 1 < chars.len() && chars[i + 1].eq_ignore_ascii_case(&'x') {
                i += 2;
                while i < chars.len() && chars[i].is_ascii_hexdigit() {
                    i += 1;
                }
                let hex: String = chars[start + 2..i].iter().collect();
                let value = i64::from_str_radix(&hex, 16)
                    .map_err(|_| anyhow::anyhow!("bad hex literal in condition"))?;
                tokens.push(Tok::Int(value));
            } else {
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let dec: String = chars[start..i].iter().collect();
                let mut value: i64 = dec
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad number in condition"))?;
                // KB / MB size suffixes (attached, as in `filesize < 500KB`).
                let rest: String = chars[i..(i + 2).min(chars.len())].iter().collect();
                if rest == "KB" {
                    value *= 1024;
                    i += 2;
                } else if rest == "MB" {
                    value *= 1024 * 1024;
                    i += 2;
                }
                tokens.push(Tok::Int(value));
            }
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let mut name = String::new();
            while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
                name.push(chars[i]);
                i += 1;
            }
            tokens.push(Tok::Ident(name));
            continue;
        }
        match c {
            '(' => {
                tokens.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                tokens.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                tokens.push(Tok::LBracket);
                i += 1;
            }
            ']' => {
                tokens.push(Tok::RBracket);
                i += 1;
            }
            ',' => {
                tokens.push(Tok::Comma);
                i += 1;
            }
            _ => {
                let two: String = chars[i..(i + 2).min(chars.len())].iter().collect();
                if ["==", "!=", "<=", ">="].contains(&two.as_str()) {
                    tokens.push(Tok::Op(two));
                    i += 2;
                    continue;
                }
                if "<>+-*/%&|^.".contains(c) {
                    tokens.push(Tok::Op(c.to_string()));
                    i += 1;
                    continue;
                }
                anyhow::bail!("unexpected character '{c}' in condition");
            }
        }
    }
    Ok(tokens)
}

struct ExprParser {
    tokens: Vec<Tok>,
    pos: usize,
    /// Declared string identifiers (`$a`, …) for `them` / `$a*` sets.
    declared: Vec<String>,
}

/// Quantifier of an `of` expression: `any of`, `all of`, `N of`, `N% of`.
#[derive(Debug, Clone, Copy)]
enum OfQuant {
    Any,
    All,
    Count(usize),
    Percent(usize),
}

impl ExprParser {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn peek_at(&self, ahead: usize) -> Option<&Tok> {
        self.tokens.get(self.pos + ahead)
    }

    fn eat(&mut self) -> Option<Tok> {
        let tok = self.tokens.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn parse(mut self) -> anyhow::Result<Expr> {
        let expr = self.parse_or()?;
        if self.pos != self.tokens.len() {
            anyhow::bail!("trailing tokens in condition");
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Ident(k)) if k == "or") {
            self.eat();
            let right = self.parse_and()?;
            left = Expr::Binary(BinOp::Or, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_not()?;
        while matches!(self.peek(), Some(Tok::Ident(k)) if k == "and") {
            self.eat();
            let right = self.parse_not()?;
            left = Expr::Binary(BinOp::And, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> anyhow::Result<Expr> {
        if matches!(self.peek(), Some(Tok::Ident(k)) if k == "not") {
            self.eat();
            return Ok(Expr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_comparison()
    }

    fn parse_comparison(&mut self) -> anyhow::Result<Expr> {
        let left = self.parse_bitor()?;
        let op = match self.peek() {
            Some(Tok::Op(op)) if ["==", "!=", "<", ">", "<=", ">="].contains(&op.as_str()) => {
                op.clone()
            }
            Some(Tok::Ident(k))
                if matches!(
                    k.as_str(),
                    "contains" | "startswith" | "endswith" | "matches"
                ) =>
            {
                k.clone()
            }
            _ => return Ok(left),
        };
        self.eat();
        let right = self.parse_bitor()?;
        let binop = match op.as_str() {
            "==" => BinOp::Eq,
            "!=" => BinOp::Ne,
            "<" => BinOp::Lt,
            ">" => BinOp::Gt,
            "<=" => BinOp::Le,
            ">=" => BinOp::Ge,
            "contains" => BinOp::Contains,
            "startswith" => BinOp::StartsWith,
            "endswith" => BinOp::EndsWith,
            "matches" => BinOp::Matches,
            _ => anyhow::bail!("unknown comparison operator '{op}'"),
        };
        Ok(Expr::Binary(binop, Box::new(left), Box::new(right)))
    }

    fn parse_bitor(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_bitxor()?;
        while matches!(self.peek(), Some(Tok::Op(op)) if op == "|") {
            self.eat();
            let right = self.parse_bitxor()?;
            left = Expr::Binary(BinOp::BitOr, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_bitxor(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_bitand()?;
        while matches!(self.peek(), Some(Tok::Op(op)) if op == "^") {
            self.eat();
            let right = self.parse_bitand()?;
            left = Expr::Binary(BinOp::BitXor, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_bitand(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_additive()?;
        while matches!(self.peek(), Some(Tok::Op(op)) if op == "&") {
            self.eat();
            let right = self.parse_additive()?;
            left = Expr::Binary(BinOp::BitAnd, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_additive(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_multiplicative()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op(op)) if op == "+" => BinOp::Add,
                Some(Tok::Op(op)) if op == "-" => BinOp::Sub,
                _ => break,
            };
            self.eat();
            let right = self.parse_multiplicative()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_multiplicative(&mut self) -> anyhow::Result<Expr> {
        let mut left = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Op(op)) if op == "*" => BinOp::Mul,
                Some(Tok::Op(op)) if op == "/" => BinOp::Div,
                Some(Tok::Op(op)) if op == "%" => BinOp::Mod,
                _ => break,
            };
            self.eat();
            let right = self.parse_unary()?;
            left = Expr::Binary(op, Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_unary(&mut self) -> anyhow::Result<Expr> {
        if matches!(self.peek(), Some(Tok::Op(op)) if op == "-") {
            self.eat();
            return Ok(Expr::Neg(Box::new(self.parse_unary()?)));
        }
        self.parse_atom()
    }

    fn parse_atom(&mut self) -> anyhow::Result<Expr> {
        // `of` expressions: `any/all/N/N% of them | ($a, $b*) | $a*`.
        if let Some(quant) = self.peek_of_quantifier() {
            return self.parse_of_expr(quant);
        }
        match self.eat() {
            Some(Tok::Int(v)) => Ok(Expr::Lit(Value::Int(v))),
            Some(Tok::Str(s)) => Ok(Expr::Lit(Value::Str(s))),
            Some(Tok::Regex(p)) => Ok(Expr::Lit(Value::Str(p))),
            Some(Tok::StrRef(id)) => Ok(Expr::StrRef(format!("${id}"))),
            Some(Tok::CountRef(id)) => Ok(Expr::CountRef(format!("#{id}"))),
            Some(Tok::LParen) => {
                let inner = self.parse_or()?;
                if self.eat() != Some(Tok::RParen) {
                    anyhow::bail!("expected ')' in condition");
                }
                Ok(inner)
            }
            Some(Tok::Ident(name)) => self.parse_ident_atom(name),
            Some(other) => anyhow::bail!("unexpected token {other:?} in condition"),
            None => anyhow::bail!("unexpected end of condition"),
        }
    }

    /// Detect an `of` quantifier at the current position without consuming.
    fn peek_of_quantifier(&self) -> Option<OfQuant> {
        match self.peek() {
            Some(Tok::Int(n)) => match self.peek_at(1) {
                Some(Tok::Ident(k)) if k == "of" => Some(OfQuant::Count(*n as usize)),
                Some(Tok::Op(op)) if op == "%" => {
                    if matches!(self.peek_at(2), Some(Tok::Ident(k)) if k == "of") {
                        Some(OfQuant::Percent(*n as usize))
                    } else {
                        None
                    }
                }
                _ => None,
            },
            Some(Tok::Ident(k)) if (k == "any" || k == "all") => {
                if matches!(self.peek_at(1), Some(Tok::Ident(k2)) if k2 == "of") {
                    Some(if k == "any" {
                        OfQuant::Any
                    } else {
                        OfQuant::All
                    })
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Parse the set half of an `of` expression (the quantifier and `of`
    /// keyword are consumed by the caller via [`Self::peek_of_quantifier`]).
    fn parse_of_expr(&mut self, quant: OfQuant) -> anyhow::Result<Expr> {
        // Consume the quantifier tokens then the `of` keyword.
        let quant_tokens = match quant {
            OfQuant::Percent(_) => 2, // `50` `%`
            OfQuant::Any | OfQuant::All | OfQuant::Count(_) => 1,
        };
        self.pos += quant_tokens;
        if self.eat() != Some(Tok::Ident("of".to_string())) {
            anyhow::bail!("expected 'of' in of-expression");
        }

        let ids: Vec<String> = match self.peek().cloned() {
            Some(Tok::Ident(name)) if name == "them" => {
                self.eat();
                self.declared.clone()
            }
            Some(Tok::LParen) => {
                self.eat();
                let mut ids = Vec::new();
                loop {
                    ids.extend(self.parse_of_set_member()?);
                    match self.eat() {
                        Some(Tok::Comma) => continue,
                        Some(Tok::RParen) => break,
                        other => anyhow::bail!("expected ',' or ')' in of-set, got {other:?}"),
                    }
                }
                ids
            }
            Some(Tok::StrRef(_)) => self.parse_of_set_member()?,
            other => anyhow::bail!("bad of-expression set: {other:?}"),
        };

        Ok(match quant {
            OfQuant::Any => desugar_or(&ids),
            OfQuant::All => desugar_and(&ids),
            OfQuant::Count(n) => Expr::NOfThem(ids, n),
            OfQuant::Percent(p) => {
                // YARA rounds up: at least ceil(p% of the set) matches.
                let n = p
                    .saturating_mul(ids.len())
                    .div_ceil(100)
                    .min(ids.len().max(1));
                Expr::NOfThem(ids, n)
            }
        })
    }

    /// One member of an of-set: `$a` or wildcard `$a*`. Returns the
    /// matching declared identifiers.
    fn parse_of_set_member(&mut self) -> anyhow::Result<Vec<String>> {
        let Some(Tok::StrRef(id)) = self.eat() else {
            anyhow::bail!("expected '$id' in of-set");
        };
        let wildcard = if matches!(self.peek(), Some(Tok::Op(op)) if op == "*") {
            self.eat();
            true
        } else {
            false
        };
        let full = format!("${id}");
        if wildcard {
            let prefix = full.as_str();
            let matched: Vec<String> = self
                .declared
                .iter()
                .filter(|d| d.starts_with(prefix))
                .cloned()
                .collect();
            if matched.is_empty() {
                anyhow::bail!("of-set wildcard '{prefix}*' matches no strings");
            }
            Ok(matched)
        } else if self.declared.contains(&full) {
            Ok(vec![full])
        } else {
            anyhow::bail!("of-set references unknown string '{full}'")
        }
    }

    fn parse_ident_atom(&mut self, name: String) -> anyhow::Result<Expr> {
        match name.as_str() {
            "true" => Ok(Expr::Lit(Value::Bool(true))),
            "false" => Ok(Expr::Lit(Value::Bool(false))),
            "filesize" => Ok(Expr::Filesize),
            "pe" => self.parse_pe_path(),
            _ => Ok(Expr::External(name)),
        }
    }

    /// After the `pe` ident: `.field`, `.CONSTANT` or
    /// `.sections[n].name`.
    fn parse_pe_path(&mut self) -> anyhow::Result<Expr> {
        if self.eat() != Some(Tok::Op(".".to_string())) {
            anyhow::bail!("expected '.' after 'pe'");
        }
        let Some(Tok::Ident(member)) = self.eat() else {
            anyhow::bail!("expected member after 'pe.'");
        };
        if member == "sections" {
            if self.eat() != Some(Tok::LBracket) {
                anyhow::bail!("expected '[' after pe.sections");
            }
            let Some(Tok::Int(index)) = self.eat() else {
                anyhow::bail!("expected section index in pe.sections[n]");
            };
            if self.eat() != Some(Tok::RBracket) {
                anyhow::bail!("expected ']' after pe.sections[n]");
            }
            if self.eat() != Some(Tok::Op(".".to_string())) {
                anyhow::bail!("expected '.' after pe.sections[n]");
            }
            let Some(Tok::Ident(attr)) = self.eat() else {
                anyhow::bail!("expected attribute after pe.sections[n].");
            };
            if attr != "name" {
                anyhow::bail!("unsupported pe.sections attribute '{attr}' (only name)");
            }
            return Ok(Expr::PeSectionName(index.max(0) as usize));
        }
        if let Some(field) = pe_field_by_name(&member) {
            return Ok(Expr::PeField(field));
        }
        if let Some(constant) = pe_constant(&member) {
            return Ok(Expr::Lit(Value::Int(constant)));
        }
        anyhow::bail!("unknown pe module member '{member}'")
    }
}

/// Parse a condition text into an [`Expr`], desugaring the
/// `any/all/N of them` forms over the declared string identifiers.
fn parse_condition(text: &str, strings: &[RuleString]) -> anyhow::Result<Expr> {
    let trimmed = text.trim();
    let ids: Vec<String> = strings.iter().map(|rs| rs.identifier.clone()).collect();

    if trimmed == "any of them" || trimmed == "1 of them" {
        return Ok(desugar_or(&ids));
    }
    if trimmed == "all of them" {
        return Ok(desugar_and(&ids));
    }
    if let Some(n) = trimmed
        .strip_suffix("of them")
        .and_then(|prefix| prefix.trim().parse::<usize>().ok())
    {
        return Ok(Expr::NOfThem(ids, n));
    }

    let tokens = tokenize_condition(trimmed)?;
    let declared: Vec<String> = strings.iter().map(|rs| rs.identifier.clone()).collect();
    let expr = ExprParser {
        tokens,
        pos: 0,
        declared,
    }
    .parse()?;

    // Every $ref/#ref must name a declared string.
    let mut refs = Vec::new();
    expr.string_refs(&mut refs);
    for id in refs {
        if !ids.contains(&id) {
            anyhow::bail!("condition references unknown string '{id}'");
        }
    }
    Ok(expr)
}

fn desugar_or(ids: &[String]) -> Expr {
    let mut expr = Expr::Lit(Value::Bool(false));
    for id in ids {
        expr = Expr::Binary(
            BinOp::Or,
            Box::new(expr),
            Box::new(Expr::StrRef(id.clone())),
        );
    }
    expr
}

fn desugar_and(ids: &[String]) -> Expr {
    let mut expr = Expr::Lit(Value::Bool(true));
    for id in ids {
        expr = Expr::Binary(
            BinOp::And,
            Box::new(expr),
            Box::new(Expr::StrRef(id.clone())),
        );
    }
    expr
}

// ─── Hex pattern parsing ─────────────────────────────────────────────

type HexParse = (Vec<Segment>, Vec<(usize, usize)>);

fn parse_hex_body(body: &str) -> Option<HexParse> {
    const MAX_JUMP: usize = 4096;
    let mut segments: Vec<Segment> = vec![Segment::default()];
    let mut gaps: Vec<(usize, usize)> = Vec::new();

    for token in body.split_whitespace() {
        if token == "??" || token == "**" {
            let seg = segments.last_mut().expect("always one segment");
            seg.bytes.push(0);
            seg.mask.push(Some(()));
        } else if token.starts_with('[') && token.ends_with(']') {
            let inner = &token[1..token.len() - 1];
            let (min, max) = match inner.split_once('-') {
                Some((a, b)) => (a.parse().ok()?, b.parse().ok()?),
                None => {
                    let n = inner.parse().ok()?;
                    (n, n)
                }
            };
            if min > max || max > MAX_JUMP {
                return None;
            }
            match gaps.last_mut() {
                // Consecutive jumps merge additively.
                Some(prev) => {
                    prev.0 += min;
                    prev.1 += max;
                }
                None => gaps.push((min, max)),
            }
            segments.push(Segment::default());
        } else {
            let byte = u8::from_str_radix(token, 16).ok()?;
            let seg = segments.last_mut().expect("always one segment");
            seg.bytes.push(byte);
            seg.mask.push(None);
        }
    }

    // Drop empty edge segments (jump at the very start/end).
    let lead = usize::from(segments.first().is_some_and(|s| s.bytes.is_empty()));
    let tail = usize::from(segments.last().is_some_and(|s| s.bytes.is_empty()));
    if segments.len() <= lead + tail {
        return None;
    }
    let segments = segments[lead..segments.len() - tail].to_vec();
    if segments.iter().any(|s| s.bytes.is_empty()) {
        return None; // adjacent jumps with nothing between (beyond merging)
    }
    let gaps = gaps[lead..].to_vec();
    let gaps = gaps[..segments.len() - 1].to_vec();
    Some((segments, gaps))
}

fn hex_first_segment(rule_string: &RuleString) -> Option<&Segment> {
    match &rule_string.kind {
        StrKind::Hex { segments, .. } => segments.first(),
        _ => None,
    }
}

/// Match one fixed segment at `offset`.
fn segment_matches_at(segment: &Segment, data: &[u8], offset: usize) -> bool {
    if offset + segment.bytes.len() > data.len() {
        return false;
    }
    segment
        .bytes
        .iter()
        .zip(&data[offset..])
        .enumerate()
        .all(|(i, (pat, actual))| segment.mask[i].is_some() || pat == actual)
}

/// Match segments after the first, honoring inter-segment gap ranges.
fn segments_match_from(rule_string: &RuleString, data: &[u8], pos: usize, next: usize) -> bool {
    let StrKind::Hex { segments, gaps } = &rule_string.kind else {
        return true;
    };
    if next >= gaps.len() {
        return true; // every segment matched
    }
    let (gmin, gmax) = gaps[next];
    let segment = &segments[next + 1];
    for gap in gmin..=gmax {
        let p = pos + gap;
        if p <= data.len()
            && segment_matches_at(segment, data, p)
            && segments_match_from(rule_string, data, p + segment.bytes.len(), next + 1)
        {
            return true;
        }
    }
    false
}

// ─── Rule file parsing ───────────────────────────────────────────────

/// Unescape YARA string escapes (only the common ones).
fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push(b'\n'),
                Some('r') => out.push(b'\r'),
                Some('t') => out.push(b'\t'),
                Some('\\') => out.push(b'\\'),
                Some('"') => out.push(b'"'),
                Some('x') => {
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(b) = u8::from_str_radix(&hex, 16) {
                        out.push(b);
                    }
                }
                Some(other) => {
                    out.push(other as u8);
                }
                None => {}
            }
        } else {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
    }
    out
}

/// A parsed YARA-subset rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub family: Option<String>,
    pub cve: Option<String>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub strings: Vec<RuleString>,
    pub condition: Expr,
}

/// Parse a YARA-subset rule file. Multiple rules per file are supported;
/// `//` and `/* */` comments, `import`/`include` lines, rule tags and the
/// `private`/`global` modifiers are tolerated.
pub fn parse_rules(content: &str) -> anyhow::Result<Vec<Rule>> {
    // Strip comments to simplify parsing. This is quote-aware: `//` inside
    // a quoted string (e.g. a `reference = "https://…"` meta value) is
    // literal text, not a comment. Unescaped `//` or `/*` cannot occur
    // inside a `/regex/` literal (the slash would terminate it), so
    // treating them as comment starts outside strings is safe.
    let cleaned = strip_comments(content)
        .lines()
        .filter(|l| {
            let t = l.trim();
            // Ignore module imports and includes (the pe subset is built
            // in; other modules simply never match).
            !(t.starts_with("import ") || t.starts_with("include "))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut rules = Vec::new();
    let mut rest = cleaned.as_str();

    while let Some(start) = rest.find("rule ") {
        let preceded_ok = start == 0 || !rest[..start].ends_with(|c: char| c.is_alphanumeric());
        if !preceded_ok {
            // e.g. the word "rule" inside prose; skip past this occurrence.
            rest = &rest[start + 5..];
            continue;
        }
        let after_rule = &rest[start + 5..];
        let name: String = after_rule
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        if name.is_empty() {
            anyhow::bail!("rule without a name after 'rule ' keyword");
        }
        let open = after_rule
            .find('{')
            .ok_or_else(|| anyhow::anyhow!("rule {name} has no opening brace"))?;

        // Tags between the name and the opening brace: `rule X : a b {`.
        let tag_text = &after_rule[name.len()..open];
        let tags: Vec<String> = tag_text
            .trim()
            .strip_prefix(':')
            .map(|t| {
                t.split_whitespace()
                    .filter(|tag| !tag.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        // Find the matching closing brace. Braces nest inside hex strings
        // (`{ DE AD ?? EF }`), and braces inside quoted strings are literal.
        let bytes = after_rule.as_bytes();
        let mut depth = 1usize;
        let mut in_string = false;
        let mut in_regex = false;
        let mut close = None;
        let mut i = open + 1;
        while i < bytes.len() {
            let c = bytes[i];
            if in_string {
                if c == b'\\' {
                    i += 1; // skip escaped character
                } else if c == b'"' {
                    in_string = false;
                }
            } else if in_regex {
                if c == b'\\' {
                    i += 1;
                } else if c == b'/' {
                    in_regex = false;
                }
            } else if c == b'"' {
                in_string = true;
            } else if c == b'/' && depth_of_regex_start(bytes, i) {
                in_regex = true;
            } else if c == b'{' {
                depth += 1;
            } else if c == b'}' {
                depth -= 1;
                if depth == 0 {
                    close = Some(i);
                    break;
                }
            }
            i += 1;
        }
        let close = close.ok_or_else(|| anyhow::anyhow!("rule {name} is not closed"))?;

        let body = &after_rule[open + 1..close];
        rules.push(parse_rule_body(&name, &tags, body)?);
        rest = &after_rule[close + 1..];
    }

    Ok(rules)
}

/// Heuristic: does the `/` at position `i` start a regex literal (rather
/// than being a division operator)? Division never appears at the start
/// of a strings-section value, and regexes only occur there — so a slash
/// right after `= ` or whitespace inside the strings section qualifies.
/// For the body brace matcher it is enough to treat any `/` that is not
/// directly preceded by an identifier character as a regex start.
fn depth_of_regex_start(bytes: &[u8], i: usize) -> bool {
    i > 0 && !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b')' && bytes[i - 1] != b']'
}

/// Remove `//` line comments and `/* … */` block comments, preserving
/// quoted strings (a `//` inside `"https://…"` is literal) and regex
/// literals (which cannot contain unescaped `/`).
fn strip_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let chars: Vec<char> = content.chars().collect();
    let mut i = 0;
    let mut in_string = false;
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_string = false;
            }
            i += 1;
        } else if c == '"' {
            in_string = true;
            out.push(c);
            i += 1;
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            // Line comment: skip to end of line.
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            // Block comment: skip to the closing `*/`.
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    out.push('\n');
                }
                i += 1;
            }
            i = (i + 2).min(chars.len());
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn find_marker(body: &str, name: &str) -> Option<usize> {
    let needle = format!("{name}:");
    let mut from = 0;
    while let Some(idx) = body[from..].find(&needle) {
        let abs = from + idx;
        let before_ok = abs == 0 || body[..abs].ends_with(char::is_whitespace);
        let after = abs + needle.len();
        let after_ok = body[after..]
            .chars()
            .next()
            .is_some_and(|c| c.is_whitespace())
            || body[after..].is_empty();
        if before_ok && after_ok {
            return Some(abs);
        }
        from = abs + 1;
    }
    None
}

/// Split a rule body into its (meta, strings, condition) section texts.
fn split_sections(body: &str) -> (String, String, String) {
    let markers = [
        ("meta", find_marker(body, "meta")),
        ("strings", find_marker(body, "strings")),
        ("condition", find_marker(body, "condition")),
    ];
    let section = |name: &str| -> String {
        let Some(start) = markers
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, s)| *s)
        else {
            return String::new();
        };
        let content_start = start + name.len() + 1;
        // Section runs until the next marker that starts after this one.
        let end = markers
            .iter()
            .filter_map(|(_, s)| *s)
            .filter(|s| *s > start)
            .min()
            .unwrap_or(body.len());
        body[content_start..end].trim().to_string()
    };
    (section("meta"), section("strings"), section("condition"))
}

/// Parse the meta section: `key = value` pairs where a value is a
/// (possibly multi-line) quoted string, a number, or true/false. Only
/// family/cve/description are kept; other keys are tolerated and ignored.
fn parse_meta_section(
    text: &str,
    family: &mut Option<String>,
    cve: &mut Option<String>,
    description: &mut Option<String>,
) {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    loop {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut key = String::new();
        while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
            key.push(chars[i]);
            i += 1;
        }
        if key.is_empty() {
            // Unexpected character; skip it to stay resilient.
            i += 1;
            continue;
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            continue;
        }
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        let value: String = if i < chars.len() && chars[i] == '"' {
            i += 1;
            let mut v = String::new();
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                }
                v.push(chars[i]);
                i += 1;
            }
            if i < chars.len() {
                i += 1; // closing quote
            }
            v.trim().to_string()
        } else {
            let mut v = String::new();
            while i < chars.len() && !chars[i].is_whitespace() {
                v.push(chars[i]);
                i += 1;
            }
            v
        };
        match key.as_str() {
            "family" => *family = Some(value),
            "cve" => *cve = Some(value),
            "description" => *description = Some(value),
            _ => {}
        }
    }
}

fn parse_rule_body(name: &str, tags: &[String], body: &str) -> anyhow::Result<Rule> {
    let (meta_text, strings_text, condition_text) = split_sections(body);

    // ── meta ──
    let mut family = None;
    let mut cve = None;
    let mut description = None;
    parse_meta_section(&meta_text, &mut family, &mut cve, &mut description);

    // ── strings ──
    let strings = parse_strings_section(&strings_text)
        .with_context(|| format!("rule {name}: bad strings section"))?;
    // Rules without strings are valid YARA (condition-only rules gated
    // on externals, the pe module or filesize).

    // ── condition ──
    let condition = parse_condition(&condition_text, &strings)
        .with_context(|| format!("rule {name}: bad condition"))?;

    Ok(Rule {
        name: name.to_string(),
        family,
        cve,
        description,
        tags: tags.to_vec(),
        strings,
        condition,
    })
}

/// Cursor-based parser for the strings section: tolerates multi-line hex
/// patterns and arbitrary modifier order.
fn parse_strings_section(text: &str) -> anyhow::Result<Vec<RuleString>> {
    let mut strings = Vec::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    loop {
        // Skip whitespace.
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        if chars[i] != '$' {
            anyhow::bail!("expected '$identifier' in strings section");
        }
        i += 1;
        let mut identifier = String::new();
        while i < chars.len() && (chars[i].is_alphanumeric() || chars[i] == '_') {
            identifier.push(chars[i]);
            i += 1;
        }
        if identifier.is_empty() {
            anyhow::bail!("empty string identifier in strings section");
        }
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() || chars[i] != '=' {
            anyhow::bail!("expected '=' after ${identifier}");
        }
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }

        // Value: text / hex / regex.
        let kind = if chars[i] == '"' {
            let mut literal = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '"' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    literal.push(chars[i]);
                    i += 1;
                }
                literal.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                anyhow::bail!("unterminated text string for ${identifier}");
            }
            i += 1; // closing quote
            StrKind::Text {
                variants: vec![TextVariant {
                    bytes: unescape(&literal),
                    nocase: false,
                    fullword: false,
                }],
            }
        } else if chars[i] == '{' {
            let mut hex = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '}' {
                hex.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                anyhow::bail!("unterminated hex string for ${identifier}");
            }
            i += 1; // closing brace
            let Some((segments, gaps)) = parse_hex_body(&hex) else {
                anyhow::bail!("unparseable hex string for ${identifier}");
            };
            StrKind::Hex { segments, gaps }
        } else if chars[i] == '/' {
            let mut pattern = String::new();
            i += 1;
            while i < chars.len() && chars[i] != '/' {
                if chars[i] == '\\' && i + 1 < chars.len() {
                    // Keep escapes, but normalize an escaped slash (YARA
                    // writes `\/`; the regex crate wants `/`).
                    if chars[i + 1] == '/' {
                        i += 1;
                        pattern.push('/');
                        i += 1;
                        continue;
                    }
                    pattern.push(chars[i]);
                    i += 1;
                }
                pattern.push(chars[i]);
                i += 1;
            }
            if i >= chars.len() {
                anyhow::bail!("unterminated regex for ${identifier}");
            }
            i += 1; // closing slash
            StrKind::Regex {
                regex: compile_regex(&pattern, false).with_context(|| {
                    format!("regex /{pattern}/ for ${identifier} does not compile")
                })?,
                wide: false,
            }
        } else {
            anyhow::bail!("unsupported string value for ${identifier}");
        };

        // Modifiers: ascii, wide, nocase, fullword (others ignored).
        let mut ascii = false;
        let mut wide = false;
        let mut nocase = false;
        let mut fullword = false;
        loop {
            let save = i;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            if i >= chars.len() || chars[i] == '$' {
                i = save;
                break;
            }
            let mut word = String::new();
            while i < chars.len() && chars[i].is_alphanumeric() {
                word.push(chars[i]);
                i += 1;
            }
            if word.is_empty() {
                i = save;
                break;
            }
            match word.as_str() {
                "ascii" => ascii = true,
                "wide" => wide = true,
                "nocase" => nocase = true,
                "fullword" => fullword = true,
                // private, xor, base64… tolerated and ignored.
                _ => {}
            }
        }

        // Apply modifiers.
        let kind = match kind {
            StrKind::Text { variants } => {
                let base = &variants[0].bytes;
                let mut variants = Vec::new();
                // YARA default is ascii-only; explicit wide without ascii
                // searches only the wide encoding.
                if ascii || (!ascii && !wide) {
                    variants.push(TextVariant {
                        bytes: base.clone(),
                        nocase,
                        fullword,
                    });
                }
                if wide {
                    let mut wide_bytes = Vec::with_capacity(base.len() * 2);
                    for b in base {
                        wide_bytes.push(*b);
                        wide_bytes.push(0);
                    }
                    variants.push(TextVariant {
                        bytes: wide_bytes,
                        nocase,
                        fullword,
                    });
                }
                StrKind::Text { variants }
            }
            StrKind::Regex { regex, .. } => StrKind::Regex {
                regex: compile_regex(regex.as_str(), nocase)
                    .context("recompiling regex with nocase")?,
                wide,
            },
            hex @ StrKind::Hex { .. } => hex,
        };

        if matches!(&kind, StrKind::Text { variants } if variants.is_empty()) {
            anyhow::bail!("string ${identifier} produced no searchable variant");
        }

        strings.push(RuleString {
            identifier: format!("${identifier}"),
            kind,
        });
    }

    Ok(strings)
}

fn compile_regex(pattern: &str, nocase: bool) -> anyhow::Result<regex::bytes::Regex> {
    let owned;
    let pattern = if nocase {
        owned = format!("(?i){pattern}");
        &owned
    } else {
        pattern
    };
    Ok(regex::bytes::Regex::new(pattern)?)
}

// ─── Rule sets and scanning ──────────────────────────────────────────

/// Everything a rule evaluation needs beyond the rule itself.
struct ScanState<'a> {
    pe: PeInfo,
    externals: &'a ExternalVars,
    filesize: u64,
}

struct RuleEval<'a> {
    state: &'a ScanState<'a>,
    strings: &'a [RuleString],
    matched: &'a [bool],
    counts: &'a [usize],
}

impl RuleEval<'_> {
    fn matched_of(&self, id: &str) -> bool {
        self.strings
            .iter()
            .position(|rs| rs.identifier == id)
            .is_some_and(|i| self.matched[i])
    }

    fn count_of(&self, id: &str) -> i64 {
        // `#a` refers to the declaration `$a`.
        let key = id.replacen('#', "$", 1);
        self.strings
            .iter()
            .position(|rs| rs.identifier == key)
            .map(|i| self.counts[i] as i64)
            .unwrap_or(0)
    }
}

/// A set of YARA-subset rules.
#[derive(Debug, Clone)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn parse(content: &str) -> anyhow::Result<Self> {
        Ok(Self {
            rules: parse_rules(content)?,
        })
    }

    pub fn load_file(path: &Path) -> anyhow::Result<Self> {
        Self::parse(&std::fs::read_to_string(path)?)
    }

    /// Load every `*.yar`/`*.yara` file in a directory (non-recursive).
    pub fn load_dir(dir: &Path) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if matches!(ext, "yar" | "yara") {
                rules.extend(Self::load_file(&path)?.rules);
            }
        }
        Ok(Self { rules })
    }

    /// Evaluate all rules against data (no external variables).
    pub fn scan(&self, data: &[u8]) -> Vec<(&Rule, Vec<String>)> {
        self.scan_with_externals(data, &ExternalVars::new())
    }

    /// Evaluate all rules against data with caller-provided external
    /// variables (`filesize` and the `pe` module are derived from `data`).
    pub fn scan_with_externals(
        &self,
        data: &[u8],
        externals: &ExternalVars,
    ) -> Vec<(&Rule, Vec<String>)> {
        let state = ScanState {
            pe: parse_pe(data),
            externals,
            filesize: data.len() as u64,
        };
        let mut out = Vec::new();
        for rule in &self.rules {
            let counts: Vec<usize> = rule
                .strings
                .iter()
                .map(|rs| rs.count_matches(data, 1000))
                .collect();
            let matched: Vec<bool> = rule
                .strings
                .iter()
                .zip(&counts)
                .map(|(_, c)| *c > 0)
                .collect();
            let ctx = RuleEval {
                state: &state,
                strings: &rule.strings,
                matched: &matched,
                counts: &counts,
            };
            if rule.condition.eval(&ctx).truthy() {
                let ids = rule
                    .strings
                    .iter()
                    .zip(&matched)
                    .filter(|(_, m)| **m)
                    .map(|(rs, _)| rs.identifier.clone())
                    .collect();
                out.push((rule, ids));
            }
        }
        out
    }
}

/// Detector that applies a YARA-subset rule set.
pub struct YaraRuleDetector {
    ruleset: RuleSet,
    externals: ExternalVars,
}

impl YaraRuleDetector {
    pub fn new(ruleset: RuleSet) -> Self {
        Self {
            ruleset,
            externals: ExternalVars::new(),
        }
    }

    /// Build with external variables visible to conditions.
    pub fn with_externals(ruleset: RuleSet, externals: ExternalVars) -> Self {
        Self { ruleset, externals }
    }

    pub fn from_dir(dir: &Path) -> anyhow::Result<Self> {
        Ok(Self::new(RuleSet::load_dir(dir)?))
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        Ok(Self::new(RuleSet::load_file(path)?))
    }

    /// Set one external variable (typed by value form: `true`/`false` →
    /// bool, numeric → int, anything else → string).
    pub fn set_external(&mut self, name: &str, value: &str) {
        let typed = if value == "true" {
            ExternalValue::Bool(true)
        } else if value == "false" {
            ExternalValue::Bool(false)
        } else if let Ok(n) = value.parse::<i64>() {
            ExternalValue::Int(n)
        } else {
            ExternalValue::Str(value.to_string())
        };
        self.externals.insert(name.to_string(), typed);
    }
}

impl Detector for YaraRuleDetector {
    fn name(&self) -> &str {
        "yara_rules"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;

        // The scanned file's name is available as the `filename` external
        // (overridable by the caller), mirroring the yara CLI.
        let mut externals = self.externals.clone();
        if !externals.contains_key("filename") {
            if let Some(name) = target_path.file_name().and_then(|n| n.to_str()) {
                externals.insert("filename".to_string(), ExternalValue::Str(name.to_string()));
            }
        }

        let matches = self.ruleset.scan_with_externals(&data, &externals);

        Ok(matches
            .into_iter()
            .map(|(rule, ids)| {
                Finding::new(
                    "yara_rules",
                    Severity::High,
                    &format!("YARA rule match: {}", rule.name),
                    &format!(
                        "Firmware matches YARA rule '{}' ({}). Matched strings: {}.{}",
                        rule.name,
                        rule.condition.render(),
                        ids.join(", "),
                        rule.cve
                            .as_deref()
                            .map(|c| format!(" Related: {c}."))
                            .unwrap_or_default(),
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "rule": rule.name,
                    "family": rule.family,
                    "cve": rule.cve,
                    "tags": rule.tags,
                    "matched_strings": ids,
                }))
                .with_recommendation(
                    "Compare the image against a known-good baseline and review the \
                     referenced advisory.",
                )
            })
            .collect())
    }
}

/// Convenience: build a single AhoCorasick automaton over all plain-text
/// strings in a rule set (used for fast pre-filtering by callers).
pub fn build_prefilter(ruleset: &RuleSet) -> Option<AhoCorasick> {
    let patterns: Vec<Vec<u8>> = ruleset
        .rules
        .iter()
        .flat_map(|r| &r.strings)
        .filter_map(|rs| rs.plain_bytes())
        .map(|bytes| bytes.to_vec())
        .collect();
    if patterns.is_empty() {
        return None;
    }
    AhoCorasick::new(patterns).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
rule BlackLotus_MOK {
  meta:
    family = "BlackLotus"
    cve = "CVE-2023-24932"
  strings:
    $a = "MokManagerTUI" ascii
    $b = { 4D 6F 6B ?? 61 6E }
  condition:
    any of them
}

rule LoJax_Marker {
  meta:
    family = "LoJax"
  strings:
    $x = "LoJax driver"
    $y = { DE AD BE EF }
  condition:
    all of them
}
"#;

    #[test]
    fn parses_multiple_rules() {
        let set = RuleSet::parse(RULES).unwrap();
        assert_eq!(set.rules.len(), 2);
        assert_eq!(set.rules[0].name, "BlackLotus_MOK");
        assert_eq!(set.rules[0].cve.as_deref(), Some("CVE-2023-24932"));
        assert_eq!(set.rules[1].strings.len(), 2);
    }

    #[test]
    fn matches_any_of_them() {
        let set = RuleSet::parse(RULES).unwrap();
        let hits = set.scan(b"\x00\x00MokManagerTUI\x00");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].0.name, "BlackLotus_MOK");
        // $a matches the literal; $b's wildcard pattern also matches
        // "MokM" + "an" inside "MokManagerTUI".
        assert_eq!(hits[0].1, vec!["$a".to_string(), "$b".to_string()]);
    }

    #[test]
    fn hex_wildcard_matches() {
        let set = RuleSet::parse(RULES).unwrap();
        // 4D 6F 6B 42 61 6E = "MokBan" — matches $b with wildcard; the
        // trailing DEADBEEF satisfies LoJax's $y so its "all of them" fires.
        let hits = set.scan(b"LoJax driver\x00MokBan\xDE\xAD\xBE\xEF");
        assert_eq!(hits.len(), 2);
        let lojax = hits.iter().find(|(r, _)| r.name == "LoJax_Marker").unwrap();
        assert_eq!(lojax.1, vec!["$x".to_string(), "$y".to_string()]);
    }

    #[test]
    fn all_of_them_requires_both() {
        let set = RuleSet::parse(RULES).unwrap();
        let hits = set.scan(b"LoJax driver only");
        assert!(hits.iter().all(|(r, _)| r.name != "LoJax_Marker"));
    }

    #[test]
    fn quiet_on_clean_data() {
        let set = RuleSet::parse(RULES).unwrap();
        assert!(set.scan(&[0u8; 256]).is_empty());
    }

    #[test]
    fn prefilter_builds() {
        let set = RuleSet::parse(RULES).unwrap();
        let ac = build_prefilter(&set).unwrap();
        assert!(ac.is_match(b"MokManagerTUI here"));
        assert!(!ac.is_match(&[0u8; 16]));
    }

    const EXPR_RULES: &str = r#"
rule Expr_Condition {
  meta:
    family = "ExprTest"
  strings:
    $a = "alpha"
    $b = "beta"
    $c = "gamma"
  condition:
    $a and $b or not $c
}

rule Jump_Pattern {
  strings:
    $j = { DE AD [4-8] BE EF }
  condition:
    $j
}

rule Fixed_Jump_Pattern {
  strings:
    $k = { 01 02 [3] 04 05 }
  condition:
    $k
}
"#;

    #[test]
    fn boolean_expression_conditions() {
        let set = RuleSet::parse(EXPR_RULES).unwrap();
        assert!(!set.scan(b"alpha beta").is_empty());
        assert!(!set.scan(b"nothing relevant").is_empty());
        assert!(set.scan(b"only gamma here").is_empty());
        assert!(!set.scan(b"alpha beta gamma").is_empty());
    }

    #[test]
    fn parenthesized_condition() {
        let rules = r#"
rule Paren_Test {
  strings:
    $a = "one"
    $b = "two"
  condition:
    $a and ($a or $b)
}
"#;
        let set = RuleSet::parse(rules).unwrap();
        assert!(!set.scan(b"one").is_empty());
        assert!(set.scan(b"two").is_empty());
        assert!(set.scan(b"neither").is_empty());
    }

    #[test]
    fn unknown_identifier_rejected() {
        let rules = r#"
rule Bad_Ref {
  strings:
    $a = "one"
  condition:
    $a and $missing
}
"#;
        assert!(RuleSet::parse(rules).is_err());
    }

    #[test]
    fn range_jump_matches() {
        let set = RuleSet::parse(EXPR_RULES).unwrap();
        let jump_fired = |data: &[u8]| set.scan(data).iter().any(|(r, _)| r.name == "Jump_Pattern");
        assert!(jump_fired(b"\xDE\xAD\x01\x02\x03\x04\xBE\xEF"));
        assert!(jump_fired(
            b"\xDE\xAD\x01\x02\x03\x04\x05\x06\x07\x08\xBE\xEF"
        ));
        assert!(!jump_fired(b"\xDE\xAD\x01\x02\x03\xBE\xEF"));
        assert!(!jump_fired(
            b"\xDE\xAD\x01\x02\x03\x04\x05\x06\x07\x08\x09\xBE\xEF"
        ));
    }

    #[test]
    fn fixed_jump_matches() {
        let set = RuleSet::parse(EXPR_RULES).unwrap();
        let fixed_fired = |data: &[u8]| {
            set.scan(data)
                .iter()
                .any(|(r, _)| r.name == "Fixed_Jump_Pattern")
        };
        assert!(fixed_fired(b"\x01\x02\xAA\xBB\xCC\x04\x05"));
        assert!(!fixed_fired(b"\x01\x02\xAA\xBB\x04\x05"));
        assert!(!fixed_fired(b"\x01\x02\xAA\xBB\xCC\xDD\x04\x05"));
    }

    // ── Phase 0.8: regex strings, modifiers, pe module, externals ──

    const PARITY_RULES: &str = r#"
import "pe"

rule Regex_Marker {
  strings:
    $re = /boot[a-z]{0,4}_agent/ ascii
  condition:
    $re
}

rule Regex_Nocase {
  strings:
    $re = /IMPLANT_[A-Z]{2,6}/ nocase
  condition:
    $re
}

rule Text_Wide {
  strings:
    $w = "SetupVar" wide
  condition:
    $w
}

rule Text_Nocase_Fullword {
  strings:
    $m = "BlackLotus" nocase fullword
  condition:
    $m
}

rule Occurrence_Count {
  strings:
    $p = "PING"
  condition:
    #p >= 3
}

rule Filesize_Gate {
  strings:
    $f = "MARKER-XYZ"
  condition:
    filesize < 64KB and $f
}

rule String_Operators {
  condition:
    filename contains "shim" and filename startswith "boot"
}

rule PE_Module {
  strings:
    $mz = "payload-by-pe"
  condition:
    pe.is_pe and
    pe.machine == pe.MACHINE_I386 and
    pe.subsystem == pe.SUBSYSTEM_NATIVE and
    pe.number_of_sections == 2 and
    pe.sections[1].name == ".reloc" and
    (pe.characteristics & pe.EXECUTABLE_IMAGE) != 0 and
    $mz
}

rule External_Gate {
  strings:
    $m = "EXTERNAL-ONLY"
  condition:
    $m and deployed_environment == "production"
}

rule Multi_Line_Sections {
  meta:
    description = "sections and conditions
      can span lines"
  strings:
    $hex = { DE AD
             BE EF }
  condition:
    $hex and
      filesize > 10
}
"#;

    /// A minimal but structurally valid PE32 image.
    fn minimal_pe(payload: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        data[0..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&80u32.to_le_bytes()); // e_lfanew
        let pe_off = 80;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        data[coff..coff + 2].copy_from_slice(&0x014cu16.to_le_bytes()); // I386
        data[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // sections
        data[coff + 8..coff + 12].copy_from_slice(&0x67423F01u32.to_le_bytes()); // timestamp
        data[coff + 16..coff + 18].copy_from_slice(&224u16.to_le_bytes()); // size optional
        data[coff + 18..coff + 20].copy_from_slice(&0x0002u16.to_le_bytes()); // EXECUTABLE_IMAGE
        let opt = coff + 20;
        data[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
        data[opt + 16..opt + 20].copy_from_slice(&0x1000u32.to_le_bytes()); // entry point
        data[opt + 68..opt + 70].copy_from_slice(&1u16.to_le_bytes()); // SUBSYSTEM_NATIVE
                                                                       // Section table: two 40-byte entries at opt + 224.
        let table = opt + 224;
        data[table..table + 6].copy_from_slice(b".text\0");
        data[table + 40..table + 47].copy_from_slice(b".reloc\0");
        data.extend_from_slice(payload);
        data
    }

    #[test]
    fn regex_strings_match() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let fired = |name: &str, data: &[u8]| set.scan(data).iter().any(|(r, _)| r.name == name);
        assert!(fired("Regex_Marker", b"loading boot_agent v2\x00"));
        assert!(fired("Regex_Marker", b"bootdiag_agent"));
        assert!(!fired("Regex_Marker", b"boot-agent")); // hyphen not in class
                                                        // nocase: lowercase input matches the uppercase pattern.
        assert!(fired("Regex_Nocase", b"implant_core\x00"));
        assert!(!fired("Regex_Nocase", b"implant\x00")); // needs 2+ letters
    }

    #[test]
    fn wide_text_matches() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let fired = |name: &str, data: &[u8]| set.scan(data).iter().any(|(r, _)| r.name == name);
        // UTF-16LE "SetupVar".
        let wide: Vec<u8> = "SetupVar".bytes().flat_map(|b| [b, 0]).collect();
        assert!(fired("Text_Wide", &wide));
        // Plain ASCII must NOT match a wide-only string.
        assert!(!fired("Text_Wide", b"SetupVar"));
    }

    #[test]
    fn nocase_fullword_matches() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let fired = |name: &str, data: &[u8]| set.scan(data).iter().any(|(r, _)| r.name == name);
        assert!(fired("Text_Nocase_Fullword", b"\x00blacklotus\x00"));
        // Not fullword: embedded in identifier characters.
        assert!(!fired("Text_Nocase_Fullword", b"notblacklotushere"));
    }

    #[test]
    fn occurrence_counting() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let fired = |data: &[u8]| {
            set.scan(data)
                .iter()
                .any(|(r, _)| r.name == "Occurrence_Count")
        };
        assert!(fired(b"PINGPINGPING"));
        assert!(!fired(b"PINGPING"));
    }

    #[test]
    fn filesize_gate() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let fired = |data: &[u8]| {
            set.scan(data)
                .iter()
                .any(|(r, _)| r.name == "Filesize_Gate")
        };
        let mut small = b"MARKER-XYZ here".to_vec();
        assert!(fired(&small));
        // Same marker in a >64KB image fails the gate.
        let mut big = vec![0u8; 70 * 1024];
        big[..b"MARKER-XYZ".len()].copy_from_slice(b"MARKER-XYZ");
        assert!(!fired(&big));
        small.clear();
    }

    #[test]
    fn string_operators_on_externals() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let mut externals = ExternalVars::new();
        externals.insert(
            "filename".to_string(),
            ExternalValue::Str("bootshimx64.efi".to_string()),
        );
        let hits = set.scan_with_externals(b"irrelevant", &externals);
        assert!(hits.iter().any(|(r, _)| r.name == "String_Operators"));
        // Wrong filename → no match.
        let mut wrong = ExternalVars::new();
        wrong.insert(
            "filename".to_string(),
            ExternalValue::Str("grubx64.efi".to_string()),
        );
        let hits = set.scan_with_externals(b"irrelevant", &wrong);
        assert!(!hits.iter().any(|(r, _)| r.name == "String_Operators"));
    }

    #[test]
    fn pe_module_conditions() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let pe = minimal_pe(b"\x00payload-by-pe\x00");
        let hits = set.scan(&pe);
        assert!(
            hits.iter().any(|(r, _)| r.name == "PE_Module"),
            "PE_Module must fire: {:?}",
            hits.iter().map(|(r, _)| r.name.clone()).collect::<Vec<_>>()
        );
        // Same payload without PE headers must not fire.
        let raw = b"\x00payload-by-pe\x00".to_vec();
        let hits = set.scan(&raw);
        assert!(!hits.iter().any(|(r, _)| r.name == "PE_Module"));
    }

    #[test]
    fn external_variable_gate() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let data = b"EXTERNAL-ONLY marker".to_vec();

        // Missing external → false.
        assert!(set
            .scan(&data)
            .iter()
            .all(|(r, _)| r.name != "External_Gate"));

        let mut externals = ExternalVars::new();
        externals.insert(
            "deployed_environment".to_string(),
            ExternalValue::Str("production".to_string()),
        );
        let hits = set.scan_with_externals(&data, &externals);
        assert!(hits.iter().any(|(r, _)| r.name == "External_Gate"));
    }

    #[test]
    fn multi_line_sections_parse() {
        let set = RuleSet::parse(PARITY_RULES).unwrap();
        let fired = |data: &[u8]| {
            set.scan(data)
                .iter()
                .any(|(r, _)| r.name == "Multi_Line_Sections")
        };
        assert!(fired(b"junk\xDE\xAD\xBE\xEFjunk"));
        assert!(!fired(b"\xDE\xAD"));
        // The multi-line meta description parsed too.
        let rule = set
            .rules
            .iter()
            .find(|r| r.name == "Multi_Line_Sections")
            .unwrap();
        assert!(rule.description.as_deref().unwrap().contains("span lines"));
    }

    #[test]
    fn rule_tags_and_imports_tolerated() {
        let rules = r#"
import "pe"
import "elf"

private rule Tagged_Rule : bootkit uefi stage2 {
  strings:
    $a = "TAGGED"
  condition:
    $a
}
"#;
        let set = RuleSet::parse(rules).unwrap();
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].tags, vec!["bootkit", "uefi", "stage2"]);
        assert!(set.scan(b"has TAGGED payload").len() == 1);
    }

    #[test]
    fn of_set_expressions() {
        let rules = r#"
rule Of_Set {
  strings:
    $a1 = "alpha-one"
    $a2 = "alpha-two"
    $b = "beta"
  condition:
    2 of ($a*) and not any of ($b*) and 50% of them
}

rule Of_Set_Explicit {
  strings:
    $x = "xmark"
    $y = "ymark"
  condition:
    pe.is_pe or 1 of ($x, $y)
}
"#;
        let set = RuleSet::parse(rules).unwrap();
        let fired = |name: &str, data: &[u8]| set.scan(data).iter().any(|(r, _)| r.name == name);
        assert!(fired("Of_Set", b"alpha-one alpha-two"));
        assert!(!fired("Of_Set", b"alpha-one"));
        assert!(!fired("Of_Set", b"alpha-one beta"));
        assert!(fired("Of_Set_Explicit", b"has ymark"));
        assert!(!fired("Of_Set_Explicit", b"neither mark"));
    }

    #[test]
    fn detector_sets_filename_external() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("bootshim_implant.bin");
        std::fs::write(&target, b"TAGGED-MARKER").unwrap();

        let rules = r#"
rule Filename_Aware {
  strings:
    $a = "TAGGED-MARKER"
  condition:
    $a and filename contains "shim"
}
"#;
        let detector = YaraRuleDetector::new(RuleSet::parse(rules).unwrap());
        let findings = detector.detect(&target).unwrap();
        assert_eq!(findings.len(), 1);

        // And an unrelated filename does not fire.
        let other = dir.path().join("other.bin");
        std::fs::write(&other, b"TAGGED-MARKER").unwrap();
        assert!(detector.detect(&other).unwrap().is_empty());
    }
}
