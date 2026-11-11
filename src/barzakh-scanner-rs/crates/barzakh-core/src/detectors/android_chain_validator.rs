use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const PKVM_MAGIC: [u8; 4] = [0x70, 0x76, 0x6D, 0x66]; // "pvmf"
const DICE_MAGIC: [u8; 4] = [0x44, 0x49, 0x43, 0x45]; // "DICE"
const ANDROID_BOOT_MAGIC: [u8; 8] = [0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x21]; // "ANDROID!"
const TRUSTY_MAGIC: [u8; 4] = [0x54, 0x52, 0x55, 0x53]; // "TRUS"

#[derive(Default)]
struct ChainState {
    pkvm_present: bool,
    pkvm_signed: bool,
    dice_present: bool,
    dice_chain_valid: bool,
    gki_present: bool,
    gki_certified: bool,
    trusty_present: bool,
    trusty_signed: bool,
}

pub struct AndroidChainValidatorDetector;

impl Default for AndroidChainValidatorDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AndroidChainValidatorDetector {
    pub fn new() -> Self {
        Self
    }

    fn validate_chain(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut state = ChainState::default();

        self.check_pkvm(data, &mut state);
        self.check_dice(data, &mut state);
        self.check_gki(data, &mut state);
        self.check_trusty(data, &mut state);

        // Only report if at least one chain component is present
        let chain_components_present =
            state.pkvm_present || state.dice_present || state.gki_present || state.trusty_present;

        if !chain_components_present {
            return findings;
        }

        // Check chain integrity
        if state.pkvm_present && !state.pkvm_signed {
            findings.push(
                Finding::new(
                    "android_chain_validator",
                    Severity::Critical,
                    "pKVM hypervisor image has zeroed signature",
                    "pKVM firmware (pvmf) is present but its signature region is zeroed. \
                     An unsigned hypervisor allows guest VM escape and host memory access.",
                )
                .with_confidence(0.92)
                .with_recommendation("Ensure pKVM image is signed by the platform vendor."),
            );
        }

        if state.dice_present && !state.dice_chain_valid {
            findings.push(
                Finding::new(
                    "android_chain_validator",
                    Severity::Critical,
                    "DICE certificate chain is broken",
                    "DICE attestation markers present but CDI derivation appears invalid \
                     (zero UDS or broken chain binding). Device identity attestation is compromised.",
                )
                .with_confidence(0.88),
            );
        }

        if state.gki_present && !state.gki_certified {
            findings.push(
                Finding::new(
                    "android_chain_validator",
                    Severity::High,
                    "GKI boot image lacks certification signature",
                    "ANDROID! boot image present but boot_signature (GKI certification) \
                     region is zeroed. Kernel integrity is not bound to the AVB chain.",
                )
                .with_confidence(0.82),
            );
        }

        if state.trusty_present && !state.trusty_signed {
            findings.push(
                Finding::new(
                    "android_chain_validator",
                    Severity::Critical,
                    "Trusty TEE image has zeroed signature",
                    "Trusty secure monitor (TRUS) is present but unsigned. \
                     TEE compromise enables keystore extraction and DRM bypass.",
                )
                .with_confidence(0.90),
            );
        }

        // Check chain linkage — all four should be present for complete chain
        if chain_components_present {
            let missing: Vec<&str> = [
                (!state.pkvm_present).then_some("pKVM"),
                (!state.dice_present).then_some("DICE"),
                (!state.gki_present).then_some("GKI"),
                (!state.trusty_present).then_some("Trusty"),
            ]
            .into_iter()
            .flatten()
            .collect();

            if !missing.is_empty() && missing.len() < 4 {
                findings.push(
                    Finding::new(
                        "android_chain_validator",
                        Severity::Medium,
                        "Incomplete Android boot chain",
                        &format!(
                            "Boot chain is missing: {}. Partial chain leaves gaps \
                             in attestation coverage.",
                            missing.join(", ")
                        ),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "pkvm": state.pkvm_present,
                        "dice": state.dice_present,
                        "gki": state.gki_present,
                        "trusty": state.trusty_present,
                        "missing": missing,
                    })),
                );
            }
        }

        findings
    }

    fn check_pkvm(&self, data: &[u8], state: &mut ChainState) {
        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == PKVM_MAGIC {
                state.pkvm_present = true;
                // Check signature at +0x20 (32 bytes)
                if offset + 0x40 <= data.len() {
                    let sig = &data[offset + 0x20..offset + 0x40];
                    state.pkvm_signed = !sig.iter().all(|&b| b == 0x00);
                }
                return;
            }
        }
    }

    fn check_dice(&self, data: &[u8], state: &mut ChainState) {
        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == DICE_MAGIC {
                state.dice_present = true;
                // Check UDS (Unique Device Secret) at +0x10 (32 bytes)
                if offset + 0x30 <= data.len() {
                    let uds = &data[offset + 0x10..offset + 0x30];
                    state.dice_chain_valid = !uds.iter().all(|&b| b == 0x00);
                }
                return;
            }
        }
    }

    fn check_gki(&self, data: &[u8], state: &mut ChainState) {
        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 8] == ANDROID_BOOT_MAGIC {
                state.gki_present = true;
                // boot_signature indicator at +0x30 (16 bytes)
                if offset + 0x40 <= data.len() {
                    let boot_sig = &data[offset + 0x30..offset + 0x40];
                    state.gki_certified = !boot_sig.iter().all(|&b| b == 0x00);
                }
                return;
            }
        }
    }

    fn check_trusty(&self, data: &[u8], state: &mut ChainState) {
        for offset in 0..data.len().saturating_sub(64) {
            if data[offset..offset + 4] == TRUSTY_MAGIC {
                state.trusty_present = true;
                // Signature at +0x20 (32 bytes)
                if offset + 0x40 <= data.len() {
                    let sig = &data[offset + 0x20..offset + 0x40];
                    state.trusty_signed = !sig.iter().all(|&b| b == 0x00);
                }
                return;
            }
        }
    }
}

impl Detector for AndroidChainValidatorDetector {
    fn name(&self) -> &str {
        "android_chain_validator"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.validate_chain(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn fires_on_broken_chain() {
        let mut data = vec![0u8; 0x400];
        // pKVM present but unsigned (sig at +0x20 is all zeros)
        data[0x000..0x004].copy_from_slice(&PKVM_MAGIC);
        // DICE present but zeroed UDS
        data[0x100..0x104].copy_from_slice(&DICE_MAGIC);
        // GKI present but no cert
        data[0x200..0x208].copy_from_slice(&ANDROID_BOOT_MAGIC);
        // Trusty present but unsigned
        data[0x300..0x304].copy_from_slice(&TRUSTY_MAGIC);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidChainValidatorDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.len() >= 4); // All 4 components broken
        assert!(findings.iter().any(|f| f.severity == Severity::Critical));
    }

    #[test]
    fn quiet_on_signed_chain() {
        let mut data = vec![0u8; 0x400];
        // pKVM present and signed
        data[0x000..0x004].copy_from_slice(&PKVM_MAGIC);
        data[0x020..0x040].fill(0xAA); // non-zero sig
                                       // DICE present with valid UDS
        data[0x100..0x104].copy_from_slice(&DICE_MAGIC);
        data[0x110..0x130].fill(0xBB); // non-zero UDS
                                       // GKI present with cert
        data[0x200..0x208].copy_from_slice(&ANDROID_BOOT_MAGIC);
        data[0x230..0x240].fill(0xCC); // non-zero boot_sig
                                       // Trusty present and signed
        data[0x300..0x304].copy_from_slice(&TRUSTY_MAGIC);
        data[0x320..0x340].fill(0xDD); // non-zero sig

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidChainValidatorDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn quiet_on_no_android_content() {
        let data = vec![0u8; 0x400];
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();

        let detector = AndroidChainValidatorDetector::new();
        let findings = detector.detect(tmp.path()).unwrap();
        assert!(findings.is_empty());
    }
}
