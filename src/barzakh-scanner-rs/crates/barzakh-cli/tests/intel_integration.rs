//! Integration tests for the bundled intel artifacts shipped at the repo
//! root: `intel-feeds/barzakh-default.json` and `intel-rules/*.yar`.

use std::path::{Path, PathBuf};

/// Repo root (four levels above this crate's manifest).
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..")
}

#[test]
fn bundled_ioc_feed_loads() {
    let feed =
        barzakh_intel::ioc::IocFeed::load(&repo_root().join("intel-feeds/barzakh-default.json"))
            .expect("bundled feed must parse");
    assert_eq!(feed.name, "barzakh-default");
    assert!(
        feed.iocs.len() >= 40,
        "expected a substantial feed, got {}",
        feed.iocs.len()
    );
    // Every IOC must carry a description for triage value.
    assert!(feed.iocs.iter().all(|i| !i.description.is_empty()));
}

#[test]
fn bundled_yara_rules_parse() {
    let ruleset = barzakh_intel::yara::RuleSet::load_dir(&repo_root().join("intel-rules"))
        .expect("bundled YARA rules must parse");
    assert!(
        ruleset.rules.len() >= 6,
        "expected at least 6 bundled rules, got {}",
        ruleset.rules.len()
    );
    // The bundled rules stay quiet on blank images.
    assert!(ruleset.scan(&[0u8; 4096]).is_empty());
}

#[test]
fn yara_rules_hit_known_adversary_markers() {
    // Generate the signature-plant adversary payload (planted BlackLotus,
    // CosmicStrand, MoonBounce markers) and verify the bundled rules fire.
    let payloads = barzakh_adversary::create_all_payloads();
    let payload = payloads
        .iter()
        .find(|p| p.name() == "signature_plant")
        .expect("signature_plant payload exists");
    let data = payload
        .generate(&barzakh_adversary::PayloadConfig {
            arch: barzakh_adversary::Arch::X86_64,
            size: 0x10000,
        })
        .unwrap();

    let ruleset = barzakh_intel::yara::RuleSet::load_dir(&repo_root().join("intel-rules")).unwrap();
    let hits = ruleset.scan(&data);
    let names: Vec<&str> = hits.iter().map(|(r, _)| r.name.as_str()).collect();
    assert!(
        names.contains(&"BlackLotus_MOK_Abuse"),
        "BlackLotus rule must fire on planted marker; fired: {names:?}"
    );
    assert!(
        names.contains(&"CosmicStrand_Hook"),
        "CosmicStrand rule must fire on planted marker; fired: {names:?}"
    );
    assert!(
        names.contains(&"MoonBounce_SPI_Implant"),
        "MoonBounce rule must fire on planted marker; fired: {names:?}"
    );
}

#[test]
fn ioc_feed_detector_flags_known_adversary_markers() {
    let payloads = barzakh_adversary::create_all_payloads();
    let payload = payloads
        .iter()
        .find(|p| p.name() == "signature_plant")
        .expect("signature_plant payload exists");
    let data = payload
        .generate(&barzakh_adversary::PayloadConfig {
            arch: barzakh_adversary::Arch::X86_64,
            size: 0x10000,
        })
        .unwrap();

    let feed =
        barzakh_intel::ioc::IocFeed::load(&repo_root().join("intel-feeds/barzakh-default.json"))
            .unwrap();
    let hits = feed.match_image(&data);
    let families: Vec<&str> = hits
        .iter()
        .filter_map(|(ioc, _)| ioc.family.as_deref())
        .collect();
    assert!(
        families.contains(&"BlackLotus"),
        "feed must flag BlackLotus marker; families: {families:?}"
    );
}
