#![no_main]
use barzakh_core::{detectors, Detector, ScanContext};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = barzakh_core::tcg::variable_measurements(data);
    let context = ScanContext::from_bytes("fuzz.bin".into(), data.to_vec());
    // Direct invocation intentionally bypasses scanner panic recovery, so
    // libFuzzer can save and minimize the crashing input.
    let targets: Vec<Box<dyn Detector>> = vec![
        Box::new(detectors::firmware_volume::FirmwareVolumeDetector::new()),
        Box::new(detectors::dmar_enforcement::DmarEnforcementDetector::new()),
        Box::new(detectors::ivrs_table::IvrsTableDetector::new()),
        Box::new(detectors::nvram_verifier::NvramVerifierDetector::new()),
        Box::new(detectors::capsule_update::CapsuleUpdateDetector::new()),
    ];
    for detector in targets {
        let _ = detector.detect_context(&context);
    }
});
