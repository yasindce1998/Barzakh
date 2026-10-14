//! Structural feature extraction from firmware images.

use serde::Serialize;

/// Feature vector extracted from a firmware image.
///
/// All features are order-0 statistics computable in a single pass — this
/// keeps extraction fast enough for the <500ms full-sweep latency budget.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct FirmwareFeatures {
    /// Image size in bytes (log2-scaled in the vector).
    pub size_bytes: u64,
    /// Shannon entropy over byte histogram (0..8 bits/byte).
    pub entropy: f64,
    /// Fraction of printable ASCII bytes.
    pub printable_ratio: f64,
    /// Fraction of zero bytes.
    pub zero_ratio: f64,
    /// Number of `MZ` occurrences.
    pub mz_count: u64,
    /// Number of `_FVH` (firmware volume header) signatures.
    pub fvh_count: u64,
    /// Length of the longest run of identical bytes.
    pub max_run_length: u64,
    /// Longest high-entropy window (entropy ≥ 7.0 over 256-byte windows).
    pub high_entropy_window: u64,
    /// Number of extracted ASCII strings ≥ 8 chars.
    pub string_count: u64,
    /// Number of separated content islands: maximal runs of nonzero
    /// bytes split by gaps of ≥ 4 zero bytes. Injected code and data
    /// structures land at several distinct offsets; benign blobs are
    /// typically one contiguous region.
    pub content_islands: u64,
    /// Fraction of nonzero bytes that are *not* printable ASCII.
    /// Machine code and binary structures register here; legitimate
    /// string tables do not.
    pub binary_content_ratio: f64,
    /// `MZ` headers whose `e_lfanew` points at a valid `PE\0\0`
    /// signature (plausible distance: 0x40..0x400). Embedded executables
    /// form such chains; coincidental `MZ` bytes do not.
    pub valid_pe_chains: u64,
    /// Plausible PI FFS file headers (8-byte aligned, valid state, file
    /// type, and header checksum) — a proxy for real firmware-volume
    /// layout.
    pub ffs_file_count: u64,
}

impl FirmwareFeatures {
    /// Extract features from a firmware image.
    pub fn extract(data: &[u8]) -> Self {
        let len = data.len().max(1);

        let mut histogram = [0u64; 256];
        let mut printable = 0u64;
        let mut zeros = 0u64;
        // Single pass: byte histogram, printable/zero counts, and the
        // content-island state machine (a run of nonzero bytes separated
        // from the previous run by >= 4 zero bytes starts a new island).
        let mut islands = 0u64;
        let mut zero_gap = 0u32;
        for &b in data {
            histogram[b as usize] += 1;
            if (0x20..=0x7E).contains(&b) {
                printable += 1;
            }
            if b == 0 {
                zeros += 1;
                zero_gap += 1;
            } else {
                if zero_gap >= 4 {
                    islands += 1;
                }
                zero_gap = 0;
            }
        }
        let nonzero = (len as u64).saturating_sub(zeros);

        let entropy = shannon_entropy(&histogram, len);
        let mz_count = count_occurrences(data, b"MZ");
        let fvh_count = count_occurrences(data, b"_FVH");
        let (max_run_length, string_count) = run_and_string_stats(data);

        let high_entropy_window = longest_high_entropy_window(data);
        let valid_pe_chains = count_valid_pe_chains(data);
        let ffs_file_count = count_ffs_headers(data);

        Self {
            size_bytes: data.len() as u64,
            entropy,
            printable_ratio: printable as f64 / len as f64,
            zero_ratio: zeros as f64 / len as f64,
            mz_count,
            fvh_count,
            max_run_length,
            high_entropy_window,
            string_count,
            content_islands: islands,
            binary_content_ratio: if nonzero == 0 {
                0.0
            } else {
                (nonzero.saturating_sub(printable)) as f64 / nonzero as f64
            },
            valid_pe_chains,
            ffs_file_count,
        }
    }

    /// Numeric feature vector for ML consumption (13 dims, roughly 0..1
    /// scaled).
    pub fn to_vector(&self) -> Vec<f64> {
        vec![
            (self.size_bytes as f64).log2() / 24.0,
            self.entropy / 8.0,
            self.printable_ratio,
            self.zero_ratio,
            (self.mz_count as f64).ln_1p() / 10.0,
            (self.fvh_count as f64).ln_1p() / 10.0,
            (self.max_run_length as f64).ln_1p() / 16.0,
            (self.high_entropy_window as f64).ln_1p() / 14.0,
            (self.string_count as f64).ln_1p() / 12.0,
            (self.content_islands as f64).ln_1p() / 6.0,
            self.binary_content_ratio,
            (self.valid_pe_chains as f64).ln_1p() / 6.0,
            (self.ffs_file_count as f64).ln_1p() / 10.0,
        ]
    }

    pub const FEATURE_NAMES: &'static [&'static str] = &[
        "log2_size",
        "entropy",
        "printable_ratio",
        "zero_ratio",
        "mz_count",
        "fvh_count",
        "max_run_length",
        "high_entropy_window",
        "string_count",
        "content_islands",
        "binary_content_ratio",
        "valid_pe_chains",
        "ffs_file_count",
    ];
}

/// Shannon entropy in bits per byte.
pub fn shannon_entropy(histogram: &[u64; 256], total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    let mut entropy = 0.0;
    for &count in histogram {
        if count == 0 {
            continue;
        }
        let p = count as f64 / total as f64;
        entropy -= p * p.log2();
    }
    entropy
}

fn count_occurrences(data: &[u8], needle: &[u8]) -> u64 {
    if data.len() < needle.len() {
        return 0;
    }
    data.windows(needle.len()).filter(|w| *w == needle).count() as u64
}

/// Count `MZ` headers whose `e_lfanew` field points at a valid `PE\0\0`
/// signature within a plausible header distance.
fn count_valid_pe_chains(data: &[u8]) -> u64 {
    let mut chains = 0u64;
    if data.len() < 0x40 {
        return 0;
    }
    for i in 0..=data.len() - 0x40 {
        if &data[i..i + 2] != b"MZ" {
            continue;
        }
        let e_lfanew =
            u32::from_le_bytes(data[i + 0x3C..i + 0x40].try_into().unwrap_or([0; 4])) as usize;
        // Real PE headers put the signature within a few hundred bytes
        // of the DOS header; larger or wrapped distances are noise.
        if (0x40..0x400).contains(&e_lfanew)
            && i + e_lfanew + 4 <= data.len()
            && &data[i + e_lfanew..i + e_lfanew + 4] == b"PE\0\0"
        {
            chains += 1;
        }
    }
    chains
}

/// Count plausible PI FFS file headers: 8-byte aligned, valid state byte
/// (0x07 / 0xF8), a known file type, and a header checksum that sums to
/// zero. This proxies real firmware-volume layout.
fn count_ffs_headers(data: &[u8]) -> u64 {
    const MIN_HEADER: usize = 24;
    let mut count = 0u64;
    if data.len() < MIN_HEADER {
        return 0;
    }
    let mut i = 0usize;
    while i + MIN_HEADER <= data.len() {
        let state = data[i + 23];
        let file_type = data[i + 18];
        if (state == 0x07 || state == 0xF8)
            && ((0x01..=0x0E).contains(&file_type) || file_type == 0xF0)
        {
            let size = u32::from_le_bytes([data[i + 20], data[i + 21], data[i + 22], 0]) as usize;
            if size >= MIN_HEADER && i + size <= data.len() {
                let checksum: u8 = data[i..i + MIN_HEADER]
                    .iter()
                    .fold(0u8, |a, &b| a.wrapping_add(b));
                if checksum == 0 {
                    count += 1;
                }
            }
        }
        i += 8;
    }
    count
}

fn run_and_string_stats(data: &[u8]) -> (u64, u64) {
    let mut max_run = 0u64;
    let mut current_run = 0u64;
    let mut prev: Option<u8> = None;
    let mut strings = 0u64;
    let mut current_string = 0u64;

    for &b in data {
        if Some(b) == prev {
            current_run += 1;
        } else {
            current_run = 1;
            prev = Some(b);
        }
        max_run = max_run.max(current_run);

        if (0x20..=0x7E).contains(&b) {
            current_string += 1;
        } else {
            if current_string >= 8 {
                strings += 1;
            }
            current_string = 0;
        }
    }
    if current_string >= 8 {
        strings += 1;
    }
    (max_run, strings)
}

fn longest_high_entropy_window(data: &[u8]) -> u64 {
    const WINDOW: usize = 256;
    if data.len() < WINDOW {
        return 0;
    }
    let mut best = 0u64;
    let mut current = 0u64;
    for chunk in data.chunks(WINDOW) {
        let mut histogram = [0u64; 256];
        for &b in chunk {
            histogram[b as usize] += 1;
        }
        let entropy = shannon_entropy(&histogram, chunk.len());
        if entropy >= 7.0 {
            current += 1;
            best = best.max(current);
        } else {
            current = 0;
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_image_has_low_entropy_and_high_zero_ratio() {
        let f = FirmwareFeatures::extract(&[0u8; 4096]);
        assert!(f.entropy < 0.1);
        assert!((f.zero_ratio - 1.0).abs() < 1e-9);
        assert!(f.max_run_length >= 4096);
    }

    #[test]
    fn text_image_is_printable() {
        let text = "FIRMWARE_IMAGE_HEADER placeholder text block ".repeat(64);
        let f = FirmwareFeatures::extract(text.as_bytes());
        assert!(f.printable_ratio > 0.9);
        assert!(f.string_count > 0);
    }

    #[test]
    fn detects_pe_and_fv_signatures() {
        let mut data = vec![0u8; 2048];
        data[0..2].copy_from_slice(b"MZ");
        data[40..44].copy_from_slice(b"_FVH");
        data[200..202].copy_from_slice(b"MZ");
        let f = FirmwareFeatures::extract(&data);
        assert_eq!(f.mz_count, 2);
        assert_eq!(f.fvh_count, 1);
    }

    #[test]
    fn high_entropy_window_detected() {
        // Pseudo-random data: xorshift sequence.
        let mut x = 0x1234_5678u32;
        let data: Vec<u8> = (0..4096)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 0xFF) as u8
            })
            .collect();
        let f = FirmwareFeatures::extract(&data);
        assert!(f.high_entropy_window > 0, "expected high-entropy windows");
        assert!(f.entropy > 7.0);
    }

    #[test]
    fn vector_dimensions_match_names() {
        let f = FirmwareFeatures::extract(b"hello world 12345678");
        assert_eq!(f.to_vector().len(), FirmwareFeatures::FEATURE_NAMES.len());
    }
}
