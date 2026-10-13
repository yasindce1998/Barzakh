use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;

/// A known-good golden baseline for a firmware image.
///
/// Rich baselines are captured from a QEMU/OVMF + swtpm run via
/// `scripts/capture-baseline.sh` (PCR dump, memory map, event log) and
/// combined with structural hashes of the image itself.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Baseline {
    #[serde(default)]
    pub pcr_values: Option<HashMap<String, String>>,
    #[serde(default)]
    pub memory_map: Option<Vec<MemoryMapEntry>>,
    #[serde(default)]
    pub boot_services_table: Option<serde_json::Value>,
    #[serde(default)]
    pub event_log: Option<Vec<serde_json::Value>>,
    /// SHA-256 of the known-good firmware image.
    #[serde(default)]
    pub image_sha256: Option<String>,
    /// Size of the known-good image in bytes.
    #[serde(default)]
    pub image_size: Option<u64>,
    /// Where the baseline was captured (e.g. QEMU/OVMF run timestamp).
    #[serde(default)]
    pub source: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMapEntry {
    pub address: u64,
    pub size: u64,
    #[serde(default)]
    pub mem_type: Option<String>,
}

impl Baseline {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let baseline: Baseline = serde_json::from_str(&content)?;
        Ok(baseline)
    }

    /// Compute the SHA-256 of a firmware image.
    pub fn image_hash(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        digest.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Build a rich baseline from a known-good image plus optional capture
    /// artifacts:
    ///
    /// - `pcrs`: output of `tpm2_pcrread` (lines like `  0 : 0x0000… <hex>`)
    /// - `memmap`: lines like `0x000000007EF10000-0x000000007F000000 04 Conventional`
    /// - `eventlog`: TCG event log dump (one JSON object per line, or raw
    ///   text lines wrapped as JSON strings)
    pub fn capture(
        image: &[u8],
        pcrs: Option<&str>,
        memmap: Option<&str>,
        eventlog: Option<&str>,
        source: &str,
    ) -> Self {
        Self {
            pcr_values: pcrs.map(parse_pcr_dump),
            memory_map: memmap.map(parse_memory_map),
            boot_services_table: None,
            event_log: eventlog.map(parse_event_log),
            image_sha256: Some(Self::image_hash(image)),
            image_size: Some(image.len() as u64),
            source: Some(source.to_string()),
        }
    }

    /// True when the baseline carries real capture data (not a stub).
    pub fn is_populated(&self) -> bool {
        self.pcr_values.as_ref().is_some_and(|m| !m.is_empty())
            || self.memory_map.as_ref().is_some_and(|m| !m.is_empty())
            || self.event_log.as_ref().is_some_and(|m| !m.is_empty())
            || self.image_sha256.is_some()
    }
}

/// Parse `tpm2_pcrread`-style output:
///
/// ```text
///   sha256:
///     0 : 0x0000000000000000000000000000000000000000000000000000000000000000
///     2 : 0xABCDEF...
/// ```
pub fn parse_pcr_dump(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut bank = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':') && !trimmed.starts_with('0') {
            // Bank header like "sha256:" — strip trailing colon.
            bank = trimmed.trim_end_matches(':').to_string();
            continue;
        }
        // PCR line: "0 : 0x<hex>"
        if let Some((index, value)) = trimmed.split_once(':') {
            let index = index.trim();
            let value = value.trim();
            if !value.starts_with("0x") {
                continue;
            }
            if index.parse::<u32>().is_ok() {
                let key = if bank.is_empty() {
                    index.to_string()
                } else {
                    format!("{bank}:{index}")
                };
                map.insert(key, value.to_string());
            }
        }
    }
    map
}

/// Parse a UEFI-style memory map dump:
///
/// ```text
/// 0x000000007EF10000-0x000000007F000000 04 Conventional
/// ```
pub fn parse_memory_map(content: &str) -> Vec<MemoryMapEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Range form: start-end [type-num] [name...]
        if let Some((range, rest)) = trimmed.split_once('-') {
            if let (Ok(start), Some(end_and_rest)) = (
                u64::from_str_radix(range.trim().trim_start_matches("0x"), 16),
                rest.split_once(char::is_whitespace),
            ) {
                let end_str = end_and_rest.0.trim().trim_start_matches("0x");
                if let Ok(end) = u64::from_str_radix(end_str, 16) {
                    let tail = end_and_rest.1.trim();
                    let (mem_type, _) = tail.split_once(char::is_whitespace).unwrap_or((tail, ""));
                    entries.push(MemoryMapEntry {
                        address: start,
                        size: end.saturating_sub(start),
                        mem_type: Some(mem_type.to_string()),
                    });
                    continue;
                }
            }
        }
        // Triple form: start size type
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            let parse_hex = |s: &str| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok();
            if let (Some(address), Some(size)) = (parse_hex(parts[0]), parse_hex(parts[1])) {
                entries.push(MemoryMapEntry {
                    address,
                    size,
                    mem_type: parts.get(2).map(|s| s.to_string()),
                });
            }
        }
    }
    entries
}

/// Parse a TCG event log capture. JSON lines pass through directly; plain
/// text lines are wrapped as JSON strings.
pub fn parse_event_log(content: &str) -> Vec<serde_json::Value> {
    let mut events = Vec::new();
    for line in content.lines().filter(|l| !l.trim().is_empty()) {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            events.push(value);
        } else {
            events.push(serde_json::Value::String(line.to_string()));
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_image_hash_and_size() {
        let image = vec![0xABu8; 1024];
        let baseline = Baseline::capture(&image, None, None, None, "test");
        assert_eq!(baseline.image_size, Some(1024));
        assert!(baseline
            .image_sha256
            .as_deref()
            .is_some_and(|h| h.len() == 64));
        assert!(baseline.is_populated());
    }

    #[test]
    fn parses_pcr_dump() {
        let dump = "\
  sha1:
    0 : 0x0000000000000000000000000000000000000000
  sha256:
    0 : 0x0000000000000000000000000000000000000000000000000000000000000000
    7 : 0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
";
        let map = parse_pcr_dump(dump);
        assert_eq!(map.len(), 3);
        assert_eq!(
            map.get("sha256:7").unwrap(),
            "0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789"
        );
    }

    #[test]
    fn parses_range_memory_map() {
        let dump = "\
0x000000007EF10000-0x000000007F000000 04 Conventional
0x0000000000000000-0x000000000009FC00 01 Usable
";
        let map = parse_memory_map(dump);
        assert_eq!(map.len(), 2);
        assert_eq!(map[0].address, 0x7EF1_0000);
        assert_eq!(map[0].size, 0xF_0000);
        assert_eq!(map[0].mem_type.as_deref(), Some("04"));
    }

    #[test]
    fn parses_triple_memory_map() {
        let map = parse_memory_map("0x1000 0x2000 07");
        assert_eq!(map.len(), 1);
        assert_eq!(map[0].address, 0x1000);
        assert_eq!(map[0].size, 0x2000);
    }

    #[test]
    fn parses_event_log_mixed() {
        let log = "{\"pcr\":7,\"type\":\"EV_EFI_VARIABLE_DRIVER_CONFIG\"}\nplain text line\n";
        let events = parse_event_log(log);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["pcr"], 7);
        assert!(events[1].is_string());
    }

    #[test]
    fn empty_baseline_not_populated() {
        assert!(!Baseline::default().is_populated());
    }
}
