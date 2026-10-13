use std::path::Path;

use anyhow::Result;

use crate::payloads::create_all_payloads;
use crate::{Arch, PayloadConfig};

/// Build a benign firmware-like image of `size` bytes: a banner string, a
/// firmware-volume header signature, and a variable ASCII string table,
/// followed by zero padding — the statistical shape of ordinary vendor
/// firmware. `seed` varies the string table so corpus pairs have feature
/// diversity (identical feature vectors make ML training degenerate).
///
/// The content layout is constrained to stay quiet under every structural
/// detector:
///
/// - **Contiguous from offset 0** — content after a zero run makes the
///   trailing length word look like an AMD microcode table size.
/// - **Capped at 0x40 bytes** — the real-mode IVT lives at 0x00..0x400;
///   bytes at 0x4C/0x54 with low non-zero segments read as INT 13h/15h
///   hooks.
/// - **Uppercase/digit alphabet only** — lowercase letters include the
///   PMIC I2C addresses 0x60/0x62, which the CLKsweep heuristic reads as
///   voltage-register writes.
pub fn benign_image(size: usize, seed: u64) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
    const MAX_CONTENT: usize = 0x40;

    let mut data = vec![0u8; size.max(0x1000)];
    let mut content: Vec<u8> = Vec::new();
    content.extend_from_slice(b"UEFI FIRMWARE IMAGE");
    content.extend_from_slice(b"_FVH");
    let extra_strings = (seed % 8) as usize;
    let mut i = 0usize;
    while content.len() < MAX_CONTENT {
        let name_len = 4 + ((seed >> (i % 32)) as usize % 8);
        if content.len() + name_len + 1 > MAX_CONTENT {
            break;
        }
        for j in 0..name_len {
            let idx = ((seed >> ((i * 7 + j) % 56)) as usize) % ALPHABET.len();
            content.push(ALPHABET[idx]);
        }
        content.push(0);
        i += 1;
        if i >= 6 + extra_strings {
            break;
        }
    }
    let n = content.len().min(data.len());
    data[..n].copy_from_slice(&content[..n]);
    data
}

/// Simple string hash for per-payload seeds.
fn name_seed(name: &str) -> u64 {
    name.bytes().fold(0xcbf2_9ce4_8422_2325u64, |acc, b| {
        (acc ^ b as u64).wrapping_mul(0x100_0000_01b3)
    })
}

pub fn generate_corpus(output_dir: &Path) -> Result<Vec<String>> {
    std::fs::create_dir_all(output_dir)?;
    let payloads = create_all_payloads();
    let mut generated = Vec::new();

    for payload in &payloads {
        let config = PayloadConfig {
            arch: payload.arch(),
            size: 0x10000,
        };

        // Generate malicious variant
        let data = payload.generate(&config)?;
        let malicious_name = format!("malicious_{}.bin", payload.name());
        let malicious_path = output_dir.join(&malicious_name);
        std::fs::write(&malicious_path, &data)?;
        generated.push(malicious_name);

        // Generate clean variant: a benign firmware-like image of the same
        // size (banner, FV header signature, string table, zero padding) —
        // pure zero blobs are degenerate for ML training and unrealistic.
        let clean_name = format!("clean_{}.bin", payload.name());
        let clean_path = output_dir.join(&clean_name);
        std::fs::write(
            &clean_path,
            benign_image(data.len(), name_seed(payload.name())),
        )?;
        generated.push(clean_name);
    }

    // Generate arch-specific variants
    for payload in &payloads {
        if payload.name() == "trampoline" {
            let config_arm = PayloadConfig {
                arch: Arch::Aarch64,
                size: 0x10000,
            };
            let data = payload.generate(&config_arm)?;
            let name = "malicious_trampoline_aarch64.bin".to_string();
            std::fs::write(output_dir.join(&name), &data)?;
            generated.push(name);
        }
    }

    Ok(generated)
}
