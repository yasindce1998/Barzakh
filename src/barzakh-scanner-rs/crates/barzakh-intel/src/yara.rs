//! A pragmatic YARA-subset rule engine.
//!
//! Supported rule syntax (sufficient for firmware IOC rules):
//!
//! ```text
//! rule BlackLotus_MOK {
//!   meta:
//!     family = "BlackLotus"
//!     cve = "CVE-2023-24932"
//!   strings:
//!     $a = "MokManagerTUI" ascii
//!     $b = { 4D 6F 6B ?? 61 6E }
//!   condition:
//!     any of them
//! }
//! ```
//!
//! Conditions: `any of them`, `N of them`, `all of them`, or boolean
//! expressions over string identifiers (`$a and $b`, `$a or $b`, `not $a`,
//! parentheses). Hex patterns support `??` wildcards and `[n-m]` jumps.

use std::path::Path;

use aho_corasick::AhoCorasick;
use anyhow::Context;

use barzakh_core::{Detector, DetectorError, Finding, Severity};

/// One fixed-length segment of a pattern (a run of literal/wildcard bytes
/// between jumps).
#[derive(Debug, Clone, Default)]
pub struct Segment {
    pub bytes: Vec<u8>,
    /// Wildcard mask: `Some(())` = any byte accepted at this position.
    pub mask: Vec<Option<()>>,
}

impl Segment {
    fn is_plain(&self) -> bool {
        self.mask.iter().all(|m| m.is_none())
    }
}

/// A string atom inside a rule.
#[derive(Debug, Clone)]
pub struct RuleString {
    pub identifier: String,
    /// Fixed byte segments; a single segment when the pattern has no jumps.
    pub segments: Vec<Segment>,
    /// Gap constraints between consecutive segments:
    /// `gaps[i] = (min, max)` bytes allowed between segment `i` and `i+1`.
    pub gaps: Vec<(usize, usize)>,
    pub is_hex: bool,
}

impl RuleString {
    /// The literal bytes when this string is a single plain segment
    /// (no wildcards, no jumps) — used for Aho-Corasick pre-filtering.
    fn plain_bytes(&self) -> Option<&[u8]> {
        if self.gaps.is_empty() && self.segments.len() == 1 && self.segments[0].is_plain() {
            Some(&self.segments[0].bytes)
        } else {
            None
        }
    }
}

/// A parsed YARA-subset rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub family: Option<String>,
    pub cve: Option<String>,
    pub description: Option<String>,
    pub strings: Vec<RuleString>,
    pub condition: Condition,
}

/// Boolean expression over string identifiers.
#[derive(Debug, Clone)]
pub enum BoolExpr {
    Id(String),
    Not(Box<BoolExpr>),
    And(Box<BoolExpr>, Box<BoolExpr>),
    Or(Box<BoolExpr>, Box<BoolExpr>),
}

impl BoolExpr {
    fn render(&self) -> String {
        match self {
            Self::Id(id) => id.clone(),
            Self::Not(inner) => format!("not {}", inner.render()),
            Self::And(a, b) => format!("({} and {})", a.render(), b.render()),
            Self::Or(a, b) => format!("({} or {})", a.render(), b.render()),
        }
    }

    fn identifiers(&self, out: &mut Vec<String>) {
        match self {
            Self::Id(id) => out.push(id.clone()),
            Self::Not(inner) => inner.identifiers(out),
            Self::And(a, b) | Self::Or(a, b) => {
                a.identifiers(out);
                b.identifiers(out);
            }
        }
    }
}

/// Evaluate a boolean expression, resolving identifiers via `id_value`.
fn eval_expr(expr: &BoolExpr, id_value: &impl Fn(&str) -> bool) -> bool {
    match expr {
        BoolExpr::Id(id) => id_value(id),
        BoolExpr::Not(inner) => !eval_expr(inner, id_value),
        BoolExpr::And(a, b) => eval_expr(a, id_value) && eval_expr(b, id_value),
        BoolExpr::Or(a, b) => eval_expr(a, id_value) || eval_expr(b, id_value),
    }
}

/// Supported condition forms.
#[derive(Debug, Clone)]
pub enum Condition {
    AnyOfThem,
    AllOfThem,
    NOfThem(usize),
    Expr(BoolExpr),
}

impl Condition {
    fn evaluate(&self, strings: &[RuleString], matched: &[bool]) -> bool {
        let id_value = |id: &str| {
            strings
                .iter()
                .position(|rs| rs.identifier == id)
                .map(|i| matched[i])
                .unwrap_or(false)
        };
        match self {
            Self::AnyOfThem => matched.iter().any(|&m| m),
            Self::AllOfThem => matched.iter().all(|&m| m),
            Self::NOfThem(n) => matched.iter().filter(|&&m| m).count() >= *n,
            Self::Expr(expr) => eval_expr(expr, &id_value),
        }
    }

    fn render(&self) -> String {
        match self {
            Self::AnyOfThem => "any of them".to_string(),
            Self::AllOfThem => "all of them".to_string(),
            Self::NOfThem(n) => format!("{n} of them"),
            Self::Expr(expr) => expr.render(),
        }
    }
}

/// Recursive-descent parser for boolean conditions:
/// `or` < `and` < `not` < `($id | ( expr ))`.
struct ConditionParser {
    tokens: Vec<String>,
    pos: usize,
}

impl ConditionParser {
    fn peek(&self) -> Option<&str> {
        self.tokens.get(self.pos).map(|s| s.as_str())
    }

    fn eat(&mut self) -> Option<String> {
        let tok = self.tokens.get(self.pos).cloned();
        if tok.is_some() {
            self.pos += 1;
        }
        tok
    }

    fn parse(mut self) -> anyhow::Result<BoolExpr> {
        let expr = self.parse_or()?;
        if self.pos != self.tokens.len() {
            anyhow::bail!("trailing tokens in condition");
        }
        Ok(expr)
    }

    fn parse_or(&mut self) -> anyhow::Result<BoolExpr> {
        let mut left = self.parse_and()?;
        while self.peek() == Some("or") {
            self.eat();
            let right = self.parse_and()?;
            left = BoolExpr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> anyhow::Result<BoolExpr> {
        let mut left = self.parse_not()?;
        while self.peek() == Some("and") {
            self.eat();
            let right = self.parse_not()?;
            left = BoolExpr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_not(&mut self) -> anyhow::Result<BoolExpr> {
        if self.peek() == Some("not") {
            self.eat();
            return Ok(BoolExpr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> anyhow::Result<BoolExpr> {
        match self.eat() {
            Some(tok) if tok.starts_with('$') => Ok(BoolExpr::Id(tok)),
            Some(tok) if tok == "(" => {
                let inner = self.parse_or()?;
                if self.eat().as_deref() != Some(")") {
                    anyhow::bail!("expected ')' in condition");
                }
                Ok(inner)
            }
            Some(tok) => anyhow::bail!("unexpected token '{tok}' in condition"),
            None => anyhow::bail!("unexpected end of condition"),
        }
    }
}

/// Parse a condition line into a [`Condition`].
fn parse_condition(cond: &str) -> anyhow::Result<Condition> {
    let trimmed = cond.trim();
    if trimmed == "any of them" {
        return Ok(Condition::AnyOfThem);
    }
    if trimmed == "all of them" {
        return Ok(Condition::AllOfThem);
    }
    if let Some(n) = trimmed
        .strip_suffix("of them")
        .and_then(|prefix| prefix.trim().parse::<usize>().ok())
    {
        return Ok(Condition::NOfThem(n));
    }

    // Tokenize: identifiers ($a), keywords (and/or/not), parentheses.
    let mut tokens: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_ident = false;
    for c in trimmed.chars() {
        match c {
            '(' | ')' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                tokens.push(c.to_string());
                in_ident = false;
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                in_ident = false;
            }
            '$' => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
                current.push('$');
                in_ident = true;
            }
            _ => {
                current.push(c);
                if !in_ident && current.len() == 1 {
                    in_ident = false;
                }
            }
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }

    let expr = ConditionParser { tokens, pos: 0 }.parse()?;
    Ok(Condition::Expr(expr))
}

/// Parse hex pattern body like `4D 6F 6B ?? 61` or `DE AD [4-8] BE` into
/// segments and inter-segment gap ranges.
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

/// Parse a YARA-subset rule file. Multiple rules per file are supported;
/// blank lines and `//` comments are ignored.
pub fn parse_rules(content: &str) -> anyhow::Result<Vec<Rule>> {
    // Strip comments to simplify parsing.
    let cleaned: String = content
        .lines()
        .map(|l| {
            if let Some(idx) = l.find("//") {
                &l[..idx]
            } else {
                l
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    let mut rules = Vec::new();
    let mut rest = cleaned.as_str();

    while let Some(start) = rest.find("rule ") {
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

        // Find the matching closing brace. Braces nest inside hex strings
        // (`{ DE AD ?? EF }`), and braces inside quoted strings are literal.
        let bytes = after_rule.as_bytes();
        let mut depth = 1usize;
        let mut in_string = false;
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
            } else if c == b'"' {
                in_string = true;
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
        rules.push(parse_rule_body(&name, body)?);
        rest = &after_rule[close + 1..];
    }

    Ok(rules)
}

fn parse_rule_body(name: &str, body: &str) -> anyhow::Result<Rule> {
    let mut family = None;
    let mut cve = None;
    let mut description = None;
    let mut strings = Vec::new();
    let mut condition = Condition::AnyOfThem;

    let mut section = "";
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "meta:" || line == "strings:" || line == "condition:" {
            section = line.trim_end_matches(':');
            continue;
        }

        match section {
            "meta" => {
                if let Some((key, value)) = line.split_once('=') {
                    let value = value.trim().trim_matches('"').to_string();
                    match key.trim() {
                        "family" => family = Some(value),
                        "cve" => cve = Some(value),
                        "description" => description = Some(value),
                        _ => {}
                    }
                }
            }
            "strings" => {
                // $id = "text" ascii  |  $id = { hex [with jumps] }
                let Some((ident, def)) = line.split_once('=') else {
                    continue;
                };
                let ident = ident.trim().to_string();
                let def = def.trim();
                if let Some(text) = def.strip_prefix('"') {
                    let text = text.strip_suffix("ascii").unwrap_or(text);
                    let text = text.trim().trim_matches('"');
                    let bytes = unescape(text);
                    if bytes.is_empty() {
                        continue;
                    }
                    strings.push(RuleString {
                        identifier: ident,
                        segments: vec![Segment {
                            mask: vec![None; bytes.len()],
                            bytes,
                        }],
                        gaps: Vec::new(),
                        is_hex: false,
                    });
                } else if let Some(hex) = def.strip_prefix('{') {
                    let hex = hex.trim().trim_end_matches('}');
                    if let Some((segments, gaps)) = parse_hex_body(hex) {
                        strings.push(RuleString {
                            identifier: ident,
                            segments,
                            gaps,
                            is_hex: true,
                        });
                    }
                }
            }
            "condition" => {
                condition =
                    parse_condition(line).with_context(|| format!("rule {name}: bad condition"))?;
            }
            _ => {}
        }
    }

    if strings.is_empty() {
        anyhow::bail!("rule {name} declares no strings");
    }
    if let Condition::Expr(expr) = &condition {
        let mut ids = Vec::new();
        expr.identifiers(&mut ids);
        for id in ids {
            if !strings.iter().any(|rs| rs.identifier == id) {
                anyhow::bail!("rule {name}: condition references unknown string '{id}'");
            }
        }
    }

    Ok(Rule {
        name: name.to_string(),
        family,
        cve,
        description,
        strings,
        condition,
    })
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
    if next >= rule_string.gaps.len() {
        return true; // every segment matched
    }
    let (gmin, gmax) = rule_string.gaps[next];
    let segment = &rule_string.segments[next + 1];
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

fn rule_string_hits(rule_string: &RuleString, data: &[u8]) -> bool {
    let Some(first) = rule_string.segments.first() else {
        return false;
    };
    if first.bytes.is_empty() || data.len() < first.bytes.len() {
        return false;
    }
    // Fast path: plain single-segment patterns use a window search.
    if let Some(bytes) = rule_string.plain_bytes() {
        return data.windows(bytes.len()).any(|w| w == bytes);
    }
    if rule_string.gaps.is_empty() {
        // Single segment with wildcards.
        let len = first.bytes.len();
        return (0..=data.len() - len).any(|i| segment_matches_at(first, data, i));
    }
    // Jump patterns: try every start of the first segment, then walk gaps.
    for start in 0..=data.len().saturating_sub(first.bytes.len()) {
        if segment_matches_at(first, data, start)
            && segments_match_from(rule_string, data, start + first.bytes.len(), 0)
        {
            return true;
        }
    }
    false
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

    /// Load every `*.yar`/`*.yara` file in a directory.
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

    /// Evaluate all rules against data; returns matching rules with their
    /// matched string identifiers.
    pub fn scan(&self, data: &[u8]) -> Vec<(&Rule, Vec<String>)> {
        let mut out = Vec::new();
        for rule in &self.rules {
            let matched: Vec<bool> = rule
                .strings
                .iter()
                .map(|rs| rule_string_hits(rs, data))
                .collect();
            if rule.condition.evaluate(&rule.strings, &matched) {
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
}

impl YaraRuleDetector {
    pub fn new(ruleset: RuleSet) -> Self {
        Self { ruleset }
    }

    pub fn from_dir(dir: &Path) -> anyhow::Result<Self> {
        Ok(Self::new(RuleSet::load_dir(dir)?))
    }

    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        Ok(Self::new(RuleSet::load_file(path)?))
    }
}

impl Detector for YaraRuleDetector {
    fn name(&self) -> &str {
        "yara_rules"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let matches = self.ruleset.scan(&data);

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
        // Only $x present, not $y → LoJax rule must NOT fire.
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
        // $a and $b → fires.
        assert!(!set.scan(b"alpha beta").is_empty());
        // neither $a nor $b, but not $c → "not $c" is true → fires.
        assert!(!set.scan(b"nothing relevant").is_empty());
        // $c present without $a/$b → (false and false) or not true → false.
        assert!(set.scan(b"only gamma here").is_empty());
        // all three: (true and true) or ... → fires.
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
        // DE AD + 4 bytes + BE EF → matches.
        assert!(jump_fired(b"\xDE\xAD\x01\x02\x03\x04\xBE\xEF"));
        // DE AD + 8 bytes + BE EF → matches (max).
        assert!(jump_fired(
            b"\xDE\xAD\x01\x02\x03\x04\x05\x06\x07\x08\xBE\xEF"
        ));
        // DE AD + 3 bytes + BE EF → below min → no match.
        assert!(!jump_fired(b"\xDE\xAD\x01\x02\x03\xBE\xEF"));
        // DE AD + 9 bytes + BE EF → above max → no match.
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
        // 01 02 + exactly 3 bytes + 04 05.
        assert!(fixed_fired(b"\x01\x02\xAA\xBB\xCC\x04\x05"));
        assert!(!fixed_fired(b"\x01\x02\xAA\xBB\x04\x05"));
        assert!(!fixed_fired(b"\x01\x02\xAA\xBB\xCC\xDD\x04\x05"));
    }
}
