use std::io::Write;

use barzakh_adversary::payloads::boot_services_hook::BootServicesHookPayload;
use barzakh_adversary::payloads::commbuffer_toctou::CommbufferToctouPayload;
use barzakh_adversary::payloads::dma_window_bypass::DmaWindowBypassPayload;
use barzakh_adversary::payloads::dmar_remap_hole::DmarRemapHolePayload;
use barzakh_adversary::payloads::fv_tamper::FirmwareVolumeTamperPayload;
use barzakh_adversary::payloads::nvram_silent_downgrade::NvramSilentDowngradePayload;
use barzakh_adversary::payloads::pe_inject::PeInjectPayload;
use barzakh_adversary::payloads::rustkit_implant::RustkitImplantPayload;
use barzakh_adversary::payloads::signature_plant::SignaturePlantPayload;
use barzakh_adversary::payloads::signed_loader_chain::SignedLoaderChainPayload;
use barzakh_adversary::payloads::trampoline::TrampolinePayload;
use barzakh_adversary::validate::validate_payload;
use barzakh_adversary::{Arch, Payload, PayloadConfig};

fn write_payload_to_temp(payload: &dyn Payload, config: &PayloadConfig) -> tempfile::NamedTempFile {
    let data = payload.generate(config).expect("payload generation failed");
    let mut tmp = tempfile::NamedTempFile::new().expect("create temp file");
    tmp.write_all(&data).expect("write temp file");
    tmp.flush().expect("flush temp file");
    tmp
}

#[test]
fn test_trampoline_x86_64_detected() {
    let payload = TrampolinePayload;
    let config = PayloadConfig {
        arch: Arch::X86_64,
        size: 0x10000,
    };
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "x86_64 trampoline should be detected");
    assert!(result.matched_findings > 0);
}

#[test]
fn test_trampoline_aarch64_detected() {
    let payload = TrampolinePayload;
    let config = PayloadConfig {
        arch: Arch::Aarch64,
        size: 0x10000,
    };
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "ARM64 trampoline should be detected");
}

#[test]
fn test_boot_services_hook_detected() {
    let payload = BootServicesHookPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "Boot Services hook should be detected");
    assert!(result.matched_findings > 0);
}

#[test]
fn test_pe_inject_detected() {
    let payload = PeInjectPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "PE injection should be detected");
}

#[test]
fn test_fv_tamper_detected() {
    let payload = FirmwareVolumeTamperPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "FV tampering should be detected");
}

#[test]
fn test_signature_plant_detected() {
    let payload = SignaturePlantPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "Signature plant should be detected");
    assert!(result.matched_findings > 0);
}

#[test]
fn test_dmar_remap_hole_detected() {
    let payload = DmarRemapHolePayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "DMAR remap hole should be detected");
}

#[test]
fn test_dma_window_bypass_detected() {
    let payload = DmaWindowBypassPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "DMA window bypass should be detected");
}

#[test]
fn test_nvram_silent_downgrade_detected() {
    let payload = NvramSilentDowngradePayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "NVRAM silent downgrade should be detected");
}

#[test]
fn test_signed_loader_chain_detected() {
    let payload = SignedLoaderChainPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "Signed loader chain should be detected");
}

#[test]
fn test_rustkit_implant_detected() {
    let payload = RustkitImplantPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "RustKit implant should be detected");
}

#[test]
fn test_commbuffer_toctou_detected() {
    let payload = CommbufferToctouPayload;
    let config = PayloadConfig::default();
    let tmp = write_payload_to_temp(&payload, &config);
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(result.detected, "CommBuffer TOCTOU should be detected");
}

#[test]
fn test_clean_file_not_detected() {
    let data = vec![0u8; 0x10000];
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(&data).unwrap();
    tmp.flush().unwrap();

    let payload = SignaturePlantPayload;
    let result = validate_payload(&payload, tmp.path()).unwrap();
    assert!(!result.detected, "Clean file should not trigger detection");
}

#[test]
#[ignore]
fn corpus_validation() {
    let dir = tempfile::tempdir().unwrap();
    let files = barzakh_adversary::corpus::generate_corpus(dir.path()).unwrap();
    assert!(!files.is_empty(), "corpus should generate files");

    let scanner = barzakh_core::BarzakhScanner::new(None);
    let metrics = scanner.validate_against_corpus(dir.path()).unwrap();

    assert!(
        metrics.true_positive_rate >= 0.8,
        "TPR should be >= 80%, got {:.1}%",
        metrics.true_positive_rate * 100.0
    );
    assert!(
        metrics.false_positive_rate <= 0.1,
        "FPR should be <= 10%, got {:.1}%",
        metrics.false_positive_rate * 100.0
    );
}
