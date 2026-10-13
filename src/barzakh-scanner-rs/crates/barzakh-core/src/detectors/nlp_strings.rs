use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// Literal ASCII text `\\x48\\x31\\xc0\\x31\\xd2\\x0f\\x05` (backslash-x escaped
/// shellcode bytes commonly embedded in obfuscated loaders).
const SHELLCODE_ESCAPE_TEXT: &[u8] = b"\\x48\\x31\\xc0\\x31\\xd2\\x0f\\x05";

const DECODER_MARKERS: &[&[u8]] = &[
    b"FromBase64String",
    b"powershell -enc",
    b"base64 -d",
    b"rundll32 javascript",
    b"xor_key=",
];

const MIN_STRING_LEN: usize = 8;
const BASE64_BLOB_MIN_LEN: usize = 40;

pub struct NlpStringsDetector;

impl Default for NlpStringsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NlpStringsDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn extract_strings(data: &[u8]) -> Vec<&[u8]> {
        let mut strings = Vec::new();
        let mut start: Option<usize> = None;
        for (i, &b) in data.iter().enumerate() {
            if (0x20..=0x7E).contains(&b) {
                if start.is_none() {
                    start = Some(i);
                }
            } else if let Some(s) = start.take() {
                if i - s >= MIN_STRING_LEN {
                    strings.push(&data[s..i]);
                }
            }
        }
        if let Some(s) = start {
            if data.len() - s >= MIN_STRING_LEN {
                strings.push(&data[s..]);
            }
        }
        strings
    }

    fn is_base64_blob(s: &[u8]) -> bool {
        s.len() >= BASE64_BLOB_MIN_LEN
            && s.iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    }

    fn obfuscation_indicators(data: &[u8], strings: &[&[u8]]) -> Vec<String> {
        let mut indicators = Vec::new();
        if Self::contains(data, SHELLCODE_ESCAPE_TEXT) {
            indicators.push("hex-escaped shellcode string".to_string());
        }
        for m in DECODER_MARKERS {
            if Self::contains(data, m) {
                indicators.push(String::from_utf8_lossy(m).into_owned());
            }
        }
        if strings.iter().any(|s| Self::is_base64_blob(s)) {
            indicators.push("long base64-encoded blob".to_string());
        }
        indicators
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        let strings = Self::extract_strings(data);
        let indicators = Self::obfuscation_indicators(data, &strings);
        if indicators.len() >= 2 {
            findings.push(
                Finding::new(
                    "nlp_strings",
                    Severity::Medium,
                    "Obfuscated payload strings detected",
                    &format!(
                        "Firmware contains {} obfuscation indicator(s): {}. Multiple \
                         decoder/deobfuscation markers in firmware strings suggest an \
                         embedded obfuscated payload rather than legitimate code.",
                        indicators.len(),
                        indicators.join(", "),
                    ),
                )
                .with_confidence(0.75)
                .with_details(serde_json::json!({
                    "indicators": indicators,
                }))
                .with_recommendation(
                    "Extract and decode the suspicious strings; correlate embedded \
                     blobs with known malware signatures; verify the string table \
                     against the vendor's stock firmware image.",
                ),
            );
        }

        let has_allocation =
            Self::contains(data, b"VirtualAlloc") || Self::contains(data, b"VirtualAllocEx");
        let has_write = Self::contains(data, b"WriteProcessMemory");
        if has_allocation && has_write {
            findings.push(
                Finding::new(
                    "nlp_strings",
                    Severity::High,
                    "Dual-use injection API sequence",
                    "Firmware contains both a process-memory allocation API \
                     (VirtualAlloc/VirtualAllocEx) and WriteProcessMemory. This API \
                     sequence is the classic shellcode injection pattern and is rarely \
                     legitimate in firmware images.",
                )
                .with_confidence(0.8)
                .with_details(serde_json::json!({
                    "apis": ["VirtualAlloc/VirtualAllocEx", "WriteProcessMemory"],
                }))
                .with_recommendation(
                    "Trace the call sites for these APIs; confirm whether the code is a \
                     signed legitimate loader or an injected payload; sandbox-execute the \
                     image and observe process manipulation behavior.",
                ),
            );
        }

        findings
    }
}

impl Detector for NlpStringsDetector {
    fn name(&self) -> &str {
        "nlp_strings"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_on_obfuscated_payload() {
        let mut v = Vec::new();
        v.extend_from_slice(b"loader stage 1\n");
        v.extend_from_slice(b"\\x48\\x31\\xc0\\x31\\xd2\\x0f\\x05 payload text\n");
        v.extend_from_slice(b"xor_key=deadbeef\n");
        let findings = NlpStringsDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium
                && f.title == "Obfuscated payload strings detected"));
    }

    #[test]
    fn fires_on_base64_blob_pair() {
        let mut v = b"powershell -enc\n".to_vec();
        v.extend_from_slice(b"TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAA\n");
        let findings = NlpStringsDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium
                && f.title == "Obfuscated payload strings detected"));
    }

    #[test]
    fn fires_on_injection_api_sequence() {
        let v = b"implant core uses VirtualAllocEx and WriteProcessMemory to inject".to_vec();
        let findings = NlpStringsDetector::new().scan(&v);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::High && f.title == "Dual-use injection API sequence"));
    }

    #[test]
    fn quiet_on_zeros_and_mz() {
        let mut v = vec![0u8; 512];
        v[0] = b'M';
        v[1] = b'Z';
        v.extend_from_slice(b"This program cannot be run in DOS mode.\r\n");
        assert!(NlpStringsDetector::new().scan(&v).is_empty());
    }

    #[test]
    fn quiet_on_plain_english() {
        let v = b"The quick brown fox jumps over the lazy dog.\nThis firmware image contains ordinary descriptive text strings only.\n".to_vec();
        assert!(NlpStringsDetector::new().scan(&v).is_empty());
    }
}
