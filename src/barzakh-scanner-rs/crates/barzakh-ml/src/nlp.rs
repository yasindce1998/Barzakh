//! NLP-grade string analysis for firmware images.
//!
//! Extracts ASCII/UTF-16 strings and scores them for obfuscation, dual-use
//! tooling references, and embedded shellcode text — the analytical core
//! behind suspicious-string triage.

use serde::Serialize;

/// A suspicious string classification.
#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousString {
    pub text: String,
    pub offset: usize,
    pub reasons: Vec<String>,
    pub score: f64,
}

/// Obfuscation / dual-use indicators searched in extracted strings.
const DECODER_MARKERS: &[&str] = &[
    "FromBase64String",
    "powershell -enc",
    "powershell -nop",
    "base64 -d",
    "openssl enc -d",
    "rundll32 javascript",
    "certutil -decode",
    "xor_key=",
];

const DUAL_USE_APIS: &[&str] = &[
    "VirtualAlloc",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "SetWindowsHookEx",
];

const SHELLCODE_TEXT: &[&str] = &["\\x48", "\\x31", "\\xc0", "\\x0f", "\\x05"];

/// Extract ASCII strings of at least `min_len` printable characters.
pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<(String, usize)> {
    let mut strings = Vec::new();
    let mut start: Option<usize> = None;
    for (i, &b) in data.iter().enumerate() {
        if (0x20..=0x7E).contains(&b) {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                strings.push((String::from_utf8_lossy(&data[s..i]).to_string(), s));
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_len {
            strings.push((String::from_utf8_lossy(&data[s..]).to_string(), s));
        }
    }
    strings
}

/// Character-level Shannon entropy of a string.
fn string_entropy(s: &str) -> f64 {
    let mut counts = [0u64; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let total = s.len() as f64;
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / total;
        entropy -= p * p.log2();
    }
    entropy
}

/// Check whether a string is a long base64-alphabet run.
fn is_base64_blob(s: &str) -> bool {
    s.len() >= 40
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}

/// Analyze extracted strings for suspicious properties.
pub fn analyze_strings(data: &[u8]) -> Vec<SuspiciousString> {
    let mut results = Vec::new();

    for (text, offset) in extract_ascii_strings(data, 8) {
        let mut reasons = Vec::new();
        let mut score: f64 = 0.0;

        for marker in DECODER_MARKERS {
            if text.contains(marker) {
                reasons.push(format!("decoder/obfuscation marker '{marker}'"));
                score += 0.35;
            }
        }
        for api in DUAL_USE_APIS {
            if text.contains(api) {
                reasons.push(format!("dual-use API '{api}'"));
                score += 0.3;
            }
        }
        if SHELLCODE_TEXT.iter().filter(|m| text.contains(*m)).count() >= 3 {
            reasons.push("hex-encoded shellcode text".to_string());
            score += 0.4;
        }
        if is_base64_blob(&text) {
            reasons.push("long base64 alphabet run".to_string());
            score += 0.25;
        }
        let entropy = string_entropy(&text);
        if entropy > 4.5
            && text.len() > 32
            && !text.chars().all(|c| c.is_ascii_hexdigit() || c == ' ')
        {
            // High-entropy text that is not simply a hex dump.
            if text.chars().any(|c| !c.is_ascii_alphanumeric()) {
                reasons.push(format!("high string entropy ({entropy:.2})"));
                score += 0.15;
            }
        }

        if !reasons.is_empty() {
            results.push(SuspiciousString {
                text: text.chars().take(120).collect(),
                offset,
                reasons,
                score: score.min(1.0),
            });
        }
    }

    results.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results.truncate(64);
    results
}

/// Aggregate string-analysis summary.
#[derive(Debug, Clone, Serialize)]
pub struct StringAnalysis {
    pub total_strings: usize,
    pub suspicious: Vec<SuspiciousString>,
    pub max_score: f64,
}

/// Run the full analysis over a firmware image.
pub fn analyze(data: &[u8]) -> StringAnalysis {
    let strings = extract_ascii_strings(data, 8);
    let suspicious = analyze_strings(data);
    let max_score = suspicious.first().map(|s| s.score).unwrap_or(0.0);
    StringAnalysis {
        total_strings: strings.len(),
        suspicious,
        max_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_embedded_strings() {
        let data = b"\x00\x00hello firmware world\x00\x00short\x00";
        let strings = extract_ascii_strings(data, 8);
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].0, "hello firmware world");
        assert_eq!(strings[0].1, 2);
    }

    #[test]
    fn flags_shellcode_text_and_decoders() {
        let mut data = b"installer payload:\n".to_vec();
        data.extend_from_slice(b"shellcode=\\x48\\x31\\xc0\\x31\\xd2\\x0f\\x05\n");
        data.extend_from_slice(b"decode=FromBase64String key=xor_key=0x37\n");
        let analysis = analyze(&data);
        assert!(analysis.max_score >= 0.6, "score {}", analysis.max_score);
        let reasons: Vec<String> = analysis
            .suspicious
            .iter()
            .flat_map(|s| s.reasons.clone())
            .collect();
        assert!(reasons.iter().any(|r| r.contains("shellcode")));
        assert!(reasons.iter().any(|r| r.contains("FromBase64")));
    }

    #[test]
    fn flags_dual_use_api_pair() {
        let data = b"inject step: VirtualAllocEx then WriteProcessMemory on target\n";
        let analysis = analyze(data);
        assert!(!analysis.suspicious.is_empty());
        assert!(analysis.max_score >= 0.5);
    }

    #[test]
    fn quiet_on_ordinary_text() {
        let data = b"UEFI DXE driver for platform initialization, version 2.7.1\nBoot menu\n";
        let analysis = analyze(data);
        assert!(analysis.suspicious.is_empty(), "{:?}", analysis.suspicious);
    }

    #[test]
    fn base64_blob_detected() {
        let data = b"c3NoZHIwMGtpdHNoaW5zaGVsbGNvZGVwYXlsb2FkZXhlY3V0ZWQ=\n";
        let analysis = analyze(data);
        assert!(analysis
            .suspicious
            .iter()
            .any(|s| s.reasons.iter().any(|r| r.contains("base64"))));
    }
}
