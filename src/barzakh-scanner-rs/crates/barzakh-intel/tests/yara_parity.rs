//! Phase 0.8 acceptance: a curated pack of real-world-style firmware
//! threat rules (regex strings, text modifiers, hex jumps, the `pe`
//! module subset, `filesize`, `of` set expressions, string operators
//! and external variables) runs unmodified through the YARA-subset
//! engine and fires on synthetic infected images.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use barzakh_intel::yara::{ExternalValue, RuleSet};

/// Repo root (four levels above this crate's manifest).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}

fn pack() -> RuleSet {
    let path = repo_root().join("intel-rules/packs/realworld-firmware.yar");
    RuleSet::load_file(&path)
        .unwrap_or_else(|e| panic!("curated pack must parse unmodified: {e:#}"))
}

/// A minimal but structurally valid PE image with the requested header
/// facts and a trailing payload blob.
fn build_pe(
    machine: u16,
    subsystem: u16,
    characteristics: u16,
    section_names: &[&str],
    entry_point: u32,
    payload: &[u8],
) -> Vec<u8> {
    let pe_off = 80usize;
    let coff = pe_off + 4;
    let opt = coff + 20;
    let size_optional = 224usize;
    let table = opt + size_optional;
    let header_len = (table + 40 * section_names.len()).max(0x200);

    let mut data = vec![0u8; header_len];
    data[0..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
    data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
    data[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
    data[coff + 2..coff + 4].copy_from_slice(&(section_names.len() as u16).to_le_bytes());
    data[coff + 16..coff + 18].copy_from_slice(&(size_optional as u16).to_le_bytes());
    data[coff + 18..coff + 20].copy_from_slice(&characteristics.to_le_bytes());
    data[opt..opt + 2].copy_from_slice(&0x10bu16.to_le_bytes()); // PE32 magic
    data[opt + 16..opt + 20].copy_from_slice(&entry_point.to_le_bytes());
    data[opt + 68..opt + 70].copy_from_slice(&subsystem.to_le_bytes());
    for (i, name) in section_names.iter().enumerate() {
        let off = table + i * 40;
        let bytes = name.as_bytes();
        data[off..off + bytes.len()].copy_from_slice(bytes);
    }
    data.extend_from_slice(payload);
    data
}

fn utf16(s: &str) -> Vec<u8> {
    s.bytes().flat_map(|b| [b, 0]).collect()
}

fn fired(set: &RuleSet, data: &[u8], externals: &HashMap<String, ExternalValue>) -> Vec<String> {
    set.scan_with_externals(data, externals)
        .into_iter()
        .map(|(rule, _)| rule.name.to_string())
        .collect()
}

#[test]
fn curated_pack_parses_unmodified() {
    let set = pack();
    let names: Vec<&str> = set.rules.iter().map(|r| r.name.as_str()).collect();
    for expected in [
        "UEFI_LoJax_SPI_Implant",
        "BlackLotus_Stage2_Bootkit",
        "MoonBounce_SPI_Implant",
        "ESPectre_SPI_Modification",
        "Bootkitty_EFI_Bootkit",
        "Deployment_Revoked_Bootloader",
        "Shim_Downgrade_Suspect",
    ] {
        assert!(
            names.contains(&expected),
            "pack is missing rule {expected}: {names:?}"
        );
    }
}

#[test]
fn lojax_rule_fires_on_modeled_sample() {
    let set = pack();
    let mut payload = b"Windir_1 service\x00".to_vec();
    payload.extend_from_slice(b"system\\CurrentControlSet\\Services\\lojaxsvc\x00");
    let image = build_pe(
        0x014c, // MACHINE_I386
        1,      // SUBSYSTEM_NATIVE
        0x0002, // EXECUTABLE_IMAGE
        &[".text", ".data"],
        0x1000,
        &payload,
    );
    let hits = fired(&set, &image, &HashMap::new());
    assert!(
        hits.contains(&"UEFI_LoJax_SPI_Implant".to_string()),
        "{hits:?}"
    );

    // Same markers in a non-PE blob: the pe gates must keep it quiet.
    let raw_hits = fired(&set, &payload, &HashMap::new());
    assert!(!raw_hits.contains(&"UEFI_LoJax_SPI_Implant".to_string()));
}

#[test]
fn blacklotus_rule_fires_on_modeled_sample() {
    let set = pack();
    let mut payload = utf16("MokManagerTUI");
    payload.extend_from_slice(b"windows\\System32\\winlogon.sys\x00");
    let image = build_pe(
        0x8664, // MACHINE_AMD64
        10,     // SUBSYSTEM_EFI_APPLICATION
        0x0002, // EXECUTABLE_IMAGE, no DLL bit
        &[".text", ".rdata"],
        0x1000,
        &payload,
    );
    let hits = fired(&set, &image, &HashMap::new());
    assert!(
        hits.contains(&"BlackLotus_Stage2_Bootkit".to_string()),
        "{hits:?}"
    );

    // A DLL-flagged image fails the characteristics gate.
    let dll_image = build_pe(
        0x8664,
        10,
        0x0002 | 0x2000, // EXECUTABLE_IMAGE | DLL
        &[".text", ".rdata"],
        0x1000,
        &payload,
    );
    let hits = fired(&set, &dll_image, &HashMap::new());
    assert!(!hits.contains(&"BlackLotus_Stage2_Bootkit".to_string()));
}

#[test]
fn moonbounce_rule_fires_on_modeled_sample() {
    let set = pack();
    let mut payload = b"map SPI_BAR1\x00".to_vec();
    payload.extend_from_slice(b"\x00eepromwriteprotect\x00");
    payload.extend_from_slice(&[0x89, 0x45, 0xF8, 0x8B, 0x4D, 0x0C, 0xE8]);
    let image = build_pe(
        0x8664, // MACHINE_AMD64
        1,      // NATIVE driver
        0x0002,
        &[".text", ".rdata", ".data"],
        0x2000, // entry_point > 0x1000
        &payload,
    );
    let hits = fired(&set, &image, &HashMap::new());
    assert!(
        hits.contains(&"MoonBounce_SPI_Implant".to_string()),
        "{hits:?}"
    );

    // First section not named .text: quiet.
    let renamed = build_pe(
        0x8664,
        1,
        0x0002,
        &["CODE", ".rdata", ".data"],
        0x2000,
        &payload,
    );
    let hits = fired(&set, &renamed, &HashMap::new());
    assert!(!hits.contains(&"MoonBounce_SPI_Implant".to_string()));
}

#[test]
fn espectre_rule_counts_occurrences() {
    let set = pack();
    let mut blob = b"SPIFLASH v1\x00".to_vec();
    blob.extend_from_slice(b"patch boot_sector_mod_a\x00");
    blob.extend_from_slice(b"patch boot_sector_mod_b\x00");
    let hits = fired(&set, &blob, &HashMap::new());
    assert!(
        hits.contains(&"ESPectre_SPI_Modification".to_string()),
        "{hits:?}"
    );

    // Only one occurrence: the #re >= 2 count gate fails.
    let mut single = b"SPIFLASH v1\x00".to_vec();
    single.extend_from_slice(b"patch boot_sector_mod_a\x00");
    let hits = fired(&set, &single, &HashMap::new());
    assert!(!hits.contains(&"ESPectre_SPI_Modification".to_string()));
}

#[test]
fn bootkitty_rule_fires_on_modeled_sample() {
    let set = pack();
    let mut payload = utf16("Ubuntu Linux");
    payload.extend_from_slice(b"\x00kitty\x00");
    let hits = fired(&set, &payload, &HashMap::new());
    assert!(
        hits.contains(&"Bootkitty_EFI_Bootkit".to_string()),
        "{hits:?}"
    );

    // Non-fullword "kitty" alone is not enough (needs 2 of them).
    let hits = fired(&set, b"notkittyhere\x00", &HashMap::new());
    assert!(!hits.contains(&"Bootkitty_EFI_Bootkit".to_string()));
}

#[test]
fn external_gated_rules_respect_externals() {
    let set = pack();
    let data = b"BUILD-REVOKED-7 payload\x00".to_vec();

    // Without the external the revocation gate stays closed.
    assert!(
        !fired(&set, &data, &HashMap::new()).contains(&"Deployment_Revoked_Bootloader".to_string())
    );

    let mut externals = HashMap::new();
    externals.insert("revoked".to_string(), ExternalValue::Bool(true));
    assert!(fired(&set, &data, &externals).contains(&"Deployment_Revoked_Bootloader".to_string()));

    // The filename-matches rule: marker + matching filename.
    let shim = b"SHIM-DOWNGRADE-MARK\x00".to_vec();
    let mut ext = HashMap::new();
    ext.insert(
        "filename".to_string(),
        ExternalValue::Str("shimx64-15.efi".to_string()),
    );
    assert!(fired(&set, &shim, &ext).contains(&"Shim_Downgrade_Suspect".to_string()));
    // Wrong filename shape: quiet.
    let mut wrong = HashMap::new();
    wrong.insert(
        "filename".to_string(),
        ExternalValue::Str("shimx64.efi".to_string()),
    );
    assert!(!fired(&set, &shim, &wrong).contains(&"Shim_Downgrade_Suspect".to_string()));
}

#[test]
fn curated_pack_is_quiet_on_clean_images() {
    let set = pack();
    // Blank data.
    assert!(fired(&set, &[0u8; 4096], &HashMap::new()).is_empty());
    // A valid, marker-free PE.
    let clean_pe = build_pe(
        0x8664,
        10,
        0x0002,
        &[".text", ".rdata", ".data"],
        0x2000,
        b"just an ordinary bootloader\x00",
    );
    assert!(fired(&set, &clean_pe, &HashMap::new()).is_empty());
    // Benign strings that could false-positive on substring matches.
    let benign = b"Ubuntu Linux is nice\x00my kitty cat\x00SystemRoot\\System32\x00";
    assert!(fired(&set, benign, &HashMap::new()).is_empty());
}
