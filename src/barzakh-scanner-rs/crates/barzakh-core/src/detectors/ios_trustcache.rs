use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// Loadable Image4 Trust Cache magic ("ltrs") plus a textual marker.
const TC_MAGIC: &[u8] = b"ltrs";
const TC_TEXT: &[u8] = b"Image4 Trust Cache";

// Model header following the magic: version(u32 LE), entry_count(u32 LE), then
// entries of [cdhash(20), hash_type(1), flags(1)] = 22 bytes each.
const TC_ENTRY_STRIDE: usize = 22;
const TC_FLAG_ADHOC: u8 = 0x01; // entry authorizes an ad-hoc / non-AppStore cdhash

pub struct IosTrustcacheDetector;

impl Default for IosTrustcacheDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl IosTrustcacheDetector {
    pub fn new() -> Self {
        Self
    }

    fn contains(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }

    fn check_at(&self, data: &[u8], magic_off: usize) -> Vec<Finding> {
        let mut findings = Vec::new();
        let hdr = magic_off + TC_MAGIC.len();
        if hdr + 8 > data.len() {
            return findings;
        }
        let count =
            u32::from_le_bytes(data[hdr + 4..hdr + 8].try_into().unwrap_or([0; 4])) as usize;
        let entries_off = hdr + 8;

        // Cap iteration to what the buffer can hold.
        let max_entries = count.min((data.len().saturating_sub(entries_off)) / TC_ENTRY_STRIDE);
        for i in 0..max_entries {
            let flags_off = entries_off + i * TC_ENTRY_STRIDE + 21;
            if flags_off >= data.len() {
                break;
            }
            if data[flags_off] & TC_FLAG_ADHOC != 0 {
                let cd_off = entries_off + i * TC_ENTRY_STRIDE;
                let cdhash_hex: String = data[cd_off..cd_off + 4]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                findings.push(
                    Finding::new(
                        "ios_trustcache",
                        Severity::Critical,
                        "Injected AMFI Trust Cache authorizes ad-hoc code",
                        &format!(
                            "An iOS Trust Cache at offset 0x{magic_off:08X} contains entry {i} \
                             (cdhash {cdhash_hex}…) flagged ad-hoc. A trust cache that authorizes \
                             ad-hoc/non-App-Store cdhashes lets unsigned binaries execute under \
                             AMFI — the mechanism jailbreaks and implants use to run arbitrary code.",
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{magic_off:08X}"),
                        "entry_index": i,
                        "entry_count": count,
                        "flags": format!("0x{:02X}", data[flags_off]),
                    }))
                    .with_recommendation(
                        "Reject dynamically loaded trust caches; only the kernelcache's static, \
                         Apple-signed trust cache should authorize executable code.",
                    ),
                );
            }
        }
        findings
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        // Gate: needs the loadable trust-cache magic (the textual marker alone is
        // informational and avoids matching arbitrary "ltrs" byte coincidences).
        if !Self::contains(data, TC_MAGIC) && !Self::contains(data, TC_TEXT) {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for (i, w) in data.windows(TC_MAGIC.len()).enumerate() {
            if w == TC_MAGIC {
                findings.extend(self.check_at(data, i));
            }
        }
        findings
    }
}

impl Detector for IosTrustcacheDetector {
    fn name(&self) -> &str {
        "ios_trustcache"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust_cache(flags: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(TC_MAGIC);
        v.extend_from_slice(&1u32.to_le_bytes()); // version
        v.extend_from_slice(&1u32.to_le_bytes()); // entry_count
        v.extend_from_slice(&[0xAB; 20]); // cdhash
        v.push(0x02); // hash_type
        v.push(flags); // flags
        v
    }

    #[test]
    fn fires_on_adhoc_entry() {
        let findings = IosTrustcacheDetector::new().scan(&trust_cache(TC_FLAG_ADHOC));
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_normal_entry() {
        assert!(IosTrustcacheDetector::new()
            .scan(&trust_cache(0x00))
            .is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(IosTrustcacheDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }
}
