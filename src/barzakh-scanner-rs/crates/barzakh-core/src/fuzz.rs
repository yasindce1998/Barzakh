//! Protocol-aware structure fuzzing for UEFI interfaces.
//!
//! Generates valid seed structures for common UEFI protocols (DHCPv6/PXE,
//! BMP image parsing, firmware capsules, HTTP Boot, TCG event log, HII
//! packages), applies structure-aware mutations, and tracks both structural
//! novelty (a coverage proxy) and which detectors fire on the mutated input —
//! detection gaps surface as mutations that no detector flags.

use std::collections::HashMap;

use serde::Serialize;

/// Protocols with structure-aware seed generators.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Dhcpv6,
    Bmp,
    Capsule,
    HttpBoot,
    TcgEvent,
    Hii,
}

impl Protocol {
    pub const ALL: &'static [Protocol] = &[
        Self::Dhcpv6,
        Self::Bmp,
        Self::Capsule,
        Self::HttpBoot,
        Self::TcgEvent,
        Self::Hii,
    ];

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "dhcpv6" | "pxe" => Some(Self::Dhcpv6),
            "bmp" | "image" => Some(Self::Bmp),
            "capsule" => Some(Self::Capsule),
            "httpboot" | "http_boot" | "http" => Some(Self::HttpBoot),
            "tcg" | "tcgevent" | "event" => Some(Self::TcgEvent),
            "hii" => Some(Self::Hii),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Dhcpv6 => "dhcpv6",
            Self::Bmp => "bmp",
            Self::Capsule => "capsule",
            Self::HttpBoot => "http_boot",
            Self::TcgEvent => "tcg_event",
            Self::Hii => "hii",
        }
    }
}

/// Mutation strategies applied to seed structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    BitFlip,
    ByteInsert,
    LengthOverflow,
    ChunkDuplicate,
    HeaderTruncate,
    MagicCorrupt,
}

impl MutationKind {
    pub const ALL: &'static [MutationKind] = &[
        Self::BitFlip,
        Self::ByteInsert,
        Self::LengthOverflow,
        Self::ChunkDuplicate,
        Self::HeaderTruncate,
        Self::MagicCorrupt,
    ];

    pub fn name(&self) -> &'static str {
        match self {
            Self::BitFlip => "bit_flip",
            Self::ByteInsert => "byte_insert",
            Self::LengthOverflow => "length_overflow",
            Self::ChunkDuplicate => "chunk_duplicate",
            Self::HeaderTruncate => "header_truncate",
            Self::MagicCorrupt => "magic_corrupt",
        }
    }
}

/// Aggregate fuzzing report.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzStats {
    pub protocol: &'static str,
    pub iterations: usize,
    /// Number of distinct (mutation kind, structure bucket) combos explored.
    pub novel_structures: usize,
    /// Mutations that produced at least one detector hit.
    pub detected_mutations: usize,
    /// Mutations no detector flagged — detection-gap candidates.
    pub undetected_mutations: usize,
    /// Hit count per detector.
    pub detector_hits: HashMap<String, usize>,
    /// Mutation count per strategy.
    pub mutations_by_kind: HashMap<String, usize>,
}

/// A small deterministic PRNG (xorshift64*) so fuzz runs are reproducible.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }
}

/// Offsets of length fields inside each seed (targets for `LengthOverflow`).
fn length_field_offsets(protocol: Protocol, seed_len: usize) -> Vec<usize> {
    match protocol {
        Protocol::Dhcpv6 => vec![5, 6], // option-len fields of first options
        Protocol::Bmp => vec![2, 18],   // file size, DIB header size
        Protocol::Capsule => vec![16, 20, 24],
        Protocol::HttpBoot => vec![],
        Protocol::TcgEvent => vec![],
        Protocol::Hii => vec![2],
    }
    .into_iter()
    .filter(|&o| o + 1 < seed_len)
    .collect()
}

/// Generate a valid seed structure for the protocol.
pub fn generate_seed(protocol: Protocol) -> Vec<u8> {
    match protocol {
        Protocol::Dhcpv6 => {
            // DHCPv6 SOLICIT: msg-type(1), transaction-id(3), options.
            let mut v = vec![1u8, 0x11, 0x22, 0x33];
            // OPTION_ORO (6), len 2, requested option 59 (OPTION_OPT_BOOTFILE_URL)
            v.extend_from_slice(&6u16.to_be_bytes());
            v.extend_from_slice(&2u16.to_be_bytes());
            v.extend_from_slice(&59u16.to_be_bytes());
            // OPTION_VENDOR_CLASS (16) with a plausible payload
            v.extend_from_slice(&16u16.to_be_bytes());
            v.extend_from_slice(&8u16.to_be_bytes());
            v.extend_from_slice(b"PXEClient");
            v
        }
        Protocol::Bmp => {
            // Minimal BMP: BITMAPFILEHEADER (14) + BITMAPINFOHEADER (40).
            let mut v = Vec::new();
            v.extend_from_slice(b"BM");
            v.extend_from_slice(&54u32.to_le_bytes()); // file size
            v.extend_from_slice(&[0; 4]); // reserved
            v.extend_from_slice(&54u32.to_le_bytes()); // pixel data offset
            v.extend_from_slice(&40u32.to_le_bytes()); // DIB header size
            v.extend_from_slice(&4i32.to_le_bytes()); // width
            v.extend_from_slice(&4i32.to_le_bytes()); // height
            v.extend_from_slice(&1u16.to_le_bytes()); // planes
            v.extend_from_slice(&24u16.to_le_bytes()); // bpp
            v.extend_from_slice(&0u32.to_le_bytes()); // compression
            v.extend_from_slice(&32u32.to_le_bytes()); // image size
            v.extend_from_slice(&[0; 16]); // resolution + colors
            v
        }
        Protocol::Capsule => {
            // EFI_CAPSULE_HEADER: GUID(16), HeaderSize(4), Flags(4),
            // CapsuleImageSize(4) + payload.
            let mut v = Vec::new();
            v.extend_from_slice(&[
                0x3B, 0x66, 0x83, 0x06, 0x13, 0x36, 0xD4, 0x11, 0x9E, 0x21, 0x34, 0x00, 0xA0, 0xC9,
                0x69, 0x72,
            ]); // EFI_CAPSULE_GUID-ish
            v.extend_from_slice(&28u32.to_le_bytes());
            v.extend_from_slice(&0x50000u32.to_le_bytes()); // CAPSULE_FLAGS_PERSIST_ACROSS_RESET
            v.extend_from_slice(&64u32.to_le_bytes());
            v.extend_from_slice(&[0xAA; 36]); // payload
            v
        }
        Protocol::HttpBoot => {
            let mut v = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n".to_vec();
            v.extend_from_slice(b"Content-Length: 512\r\n\r\n");
            v.extend_from_slice(&[0x90; 32]);
            v
        }
        Protocol::TcgEvent => {
            // TCG_PCR_EVENT2-style: PCRIndex(4), EventType(4), digest count(4),
            // algorithm id(2), digest(32), event size(4), event data.
            let mut v = Vec::new();
            v.extend_from_slice(&7u32.to_le_bytes()); // PCR[7]
            v.extend_from_slice(&0x80000003u32.to_le_bytes()); // EV_EFI_VARIABLE_DRIVER_CONFIG
            v.extend_from_slice(&1u32.to_le_bytes()); // digest count
            v.extend_from_slice(&0x000Bu16.to_le_bytes()); // SHA-256
            v.extend_from_slice(&[0x5A; 32]);
            v.extend_from_slice(&8u32.to_le_bytes());
            v.extend_from_slice(b"SecureBoot");
            v
        }
        Protocol::Hii => {
            // HII package header: length(3), type(1) + string package body.
            let mut v = Vec::new();
            v.extend_from_slice(&[0x20, 0x00, 0x00, 0x02]); // len=0x20, type=STRING
            v.extend_from_slice(&[0x44, 0x04, 0x00]); // header size, string type
            v.extend_from_slice(&[0x90; 29]);
            v
        }
    }
}

/// Structure-aware mutation engine.
pub struct ProtocolFuzzer {
    protocol: Protocol,
    rng: Rng,
    seed: Vec<u8>,
    /// Structural novelty coverage: (mutation kind, offset bucket).
    covered: std::collections::HashSet<(MutationKind, usize)>,
}

impl ProtocolFuzzer {
    pub fn new(protocol: Protocol, seed_value: u64) -> Self {
        Self {
            protocol,
            rng: Rng::new(seed_value),
            seed: generate_seed(protocol),
            covered: std::collections::HashSet::new(),
        }
    }

    /// Produce the next mutated input.
    pub fn next_mutation(&mut self) -> (Vec<u8>, MutationKind) {
        let kind = MutationKind::ALL[self.rng.below(MutationKind::ALL.len())];
        let data = self.mutate(kind);
        let bucket = if kind == MutationKind::LengthOverflow {
            0
        } else {
            self.rng.below(16)
        };
        self.covered.insert((kind, bucket));
        (data, kind)
    }

    fn mutate(&mut self, kind: MutationKind) -> Vec<u8> {
        let mut data = self.seed.clone();
        match kind {
            MutationKind::BitFlip => {
                if !data.is_empty() {
                    let idx = self.rng.below(data.len());
                    let bit = self.rng.below(8);
                    data[idx] ^= 1 << bit;
                }
            }
            MutationKind::ByteInsert => {
                let idx = self.rng.below(data.len() + 1);
                let byte = (self.rng.next_u64() & 0xFF) as u8;
                data.insert(idx, byte);
            }
            MutationKind::LengthOverflow => {
                let offsets = length_field_offsets(self.protocol, data.len());
                if let Some(&off) = offsets.first() {
                    // Write u16::MAX / u32::MAX into the length field.
                    if off + 4 <= data.len() && self.rng.next_u64() & 1 == 0 {
                        data[off..off + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                    } else if off + 2 <= data.len() {
                        data[off..off + 2].copy_from_slice(&u16::MAX.to_le_bytes());
                    }
                } else if !data.is_empty() {
                    let idx = self.rng.below(data.len());
                    data[idx] = 0xFF;
                }
            }
            MutationKind::ChunkDuplicate => {
                if data.len() > 8 {
                    let start = self.rng.below(data.len() - 4);
                    let span = 4 + self.rng.below((data.len() - start).min(32));
                    let end = (start + span).min(data.len());
                    let chunk = data[start..end].to_vec();
                    let at = self.rng.below(data.len() + 1);
                    let (head, tail) = data.split_at(at);
                    let mut out = head.to_vec();
                    out.extend_from_slice(&chunk);
                    out.extend_from_slice(tail);
                    data = out;
                }
            }
            MutationKind::HeaderTruncate => {
                let cut = 1 + self.rng.below(data.len().min(12));
                data.truncate(data.len() - cut);
            }
            MutationKind::MagicCorrupt => {
                if !data.is_empty() {
                    let idx = self.rng.below(data.len().min(4));
                    data[idx] = (self.rng.next_u64() & 0xFF) as u8;
                }
            }
        }
        data
    }

    /// Run the fuzzing loop. `detect` is invoked per mutated input and returns
    /// the names of detectors that fired on it.
    pub fn run<F>(&mut self, iterations: usize, mut detect: F) -> FuzzStats
    where
        F: FnMut(&[u8]) -> Vec<String>,
    {
        let mut detector_hits: HashMap<String, usize> = HashMap::new();
        let mut mutations_by_kind: HashMap<String, usize> = HashMap::new();
        let mut detected = 0usize;
        let mut undetected = 0usize;

        for _ in 0..iterations {
            let (input, kind) = self.next_mutation();
            *mutations_by_kind
                .entry(kind.name().to_string())
                .or_insert(0) += 1;

            let hits = detect(&input);
            if hits.is_empty() {
                undetected += 1;
            } else {
                detected += 1;
                for name in hits {
                    *detector_hits.entry(name).or_insert(0) += 1;
                }
            }
        }

        FuzzStats {
            protocol: self.protocol.name(),
            iterations,
            novel_structures: self.covered.len(),
            detected_mutations: detected,
            undetected_mutations: undetected,
            detector_hits,
            mutations_by_kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_are_well_formed() {
        assert!(generate_seed(Protocol::Dhcpv6).starts_with(&[1, 0x11, 0x22, 0x33]));
        assert!(generate_seed(Protocol::Bmp).starts_with(b"BM"));
        assert_eq!(generate_seed(Protocol::Capsule).len(), 64);
        assert!(generate_seed(Protocol::HttpBoot).starts_with(b"HTTP/1.1"));
        assert!(generate_seed(Protocol::TcgEvent).len() > 40);
        assert_eq!(generate_seed(Protocol::Hii)[3], 0x02);
    }

    #[test]
    fn mutations_change_the_seed() {
        let mut fuzzer = ProtocolFuzzer::new(Protocol::Dhcpv6, 42);
        let seed = generate_seed(Protocol::Dhcpv6);
        let mut changed = 0;
        for _ in 0..64 {
            let (input, _) = fuzzer.next_mutation();
            if input != seed {
                changed += 1;
            }
        }
        assert!(
            changed > 48,
            "expected most mutations to alter the seed, got {changed}"
        );
    }

    #[test]
    fn reproducible_with_same_seed() {
        let mut a = ProtocolFuzzer::new(Protocol::Capsule, 7);
        let mut b = ProtocolFuzzer::new(Protocol::Capsule, 7);
        for _ in 0..16 {
            let (ia, ka) = a.next_mutation();
            let (ib, kb) = b.next_mutation();
            assert_eq!((ia, ka), (ib, kb));
        }
    }

    #[test]
    fn stats_aggregate_hits() {
        let mut fuzzer = ProtocolFuzzer::new(Protocol::Bmp, 99);
        let stats = fuzzer.run(10, |input| {
            if input.len() < 10 {
                vec!["pixiefail".to_string()]
            } else {
                vec!["logofail".to_string()]
            }
        });
        assert_eq!(stats.iterations, 10);
        assert_eq!(stats.detected_mutations, 10);
        assert_eq!(stats.undetected_mutations, 0);
        assert!(stats.detector_hits.contains_key("logofail"));
        assert!(stats.novel_structures > 0);
    }

    #[test]
    fn protocol_parsing() {
        assert_eq!(Protocol::parse("dhcpv6"), Some(Protocol::Dhcpv6));
        assert_eq!(Protocol::parse("BMP"), Some(Protocol::Bmp));
        assert_eq!(Protocol::parse("nope"), None);
    }
}
