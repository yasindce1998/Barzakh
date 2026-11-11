use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::pcr_replay::{HashAlgorithm, PcrReplayEngine};
use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

#[allow(dead_code)]
const PCR_COUNT: u8 = 24;

pub struct PcrOracleDetector {
    baseline: Option<Baseline>,
}

impl PcrOracleDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        Self { baseline }
    }

    fn predict_pcrs(&self, data: &[u8]) -> HashMap<u8, Vec<u8>> {
        let mut engine = PcrReplayEngine::with_algorithm(HashAlgorithm::Sha256);

        // PCR[0]: CRTM measurement (first 64KB or firmware volume header)
        let crtm_size = data.len().min(0x10000);
        let crtm_hash = Self::sha256(&data[..crtm_size]);
        engine.extend(0, &crtm_hash);

        // PCR[1]: Platform configuration (look for configuration tables)
        if let Some(config_region) = Self::find_config_region(data) {
            let config_hash = Self::sha256(config_region);
            engine.extend(1, &config_hash);
        }

        // PCR[2]: Option ROM measurements
        for rom_region in Self::find_option_roms(data) {
            let rom_hash = Self::sha256(rom_region);
            engine.extend(2, &rom_hash);
        }

        // PCR[4]: Boot manager code
        if let Some(bootmgr) = Self::find_boot_manager(data) {
            let bm_hash = Self::sha256(bootmgr);
            engine.extend(4, &bm_hash);
        }

        // PCR[7]: Secure Boot policy
        if let Some(sb_policy) = Self::find_secureboot_policy(data) {
            let sb_hash = Self::sha256(sb_policy);
            engine.extend(7, &sb_hash);
        }

        let mut result = HashMap::new();
        for i in 0..8 {
            if let Some(val) = engine.get_pcr(i) {
                result.insert(i, val.to_vec());
            }
        }
        result
    }

    fn check_anomaly_patterns(&self, pcr_values: &HashMap<String, String>) -> Vec<Finding> {
        let mut findings = Vec::new();

        let mut parsed: HashMap<u8, Vec<u8>> = HashMap::new();
        for (idx_str, hex_val) in pcr_values {
            if let Ok(idx) = idx_str.parse::<u8>() {
                if let Some(bytes) = Self::hex_decode(hex_val) {
                    parsed.insert(idx, bytes);
                }
            }
        }

        // Check for all-zeros (uninitialized TPM)
        for (&idx, val) in &parsed {
            if idx < 8 && val.iter().all(|&b| b == 0) {
                findings.push(
                    Finding::new(
                        "pcr_oracle",
                        Severity::High,
                        &format!("PCR[{}] is all zeros - TPM may be uninitialized", idx),
                        &format!(
                            "PCR[{}] contains all zero bytes, indicating no measurements \
                             have been extended. This PCR should contain measurements \
                             during a normal measured boot.",
                            idx
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "pcr_index": idx,
                        "pattern": "all_zeros",
                    })),
                );
            }
        }

        // Check for all-ones (forced manipulation)
        for (&idx, val) in &parsed {
            if val.iter().all(|&b| b == 0xFF) {
                findings.push(
                    Finding::new(
                        "pcr_oracle",
                        Severity::Critical,
                        &format!("PCR[{}] is all 0xFF - likely manipulated", idx),
                        &format!(
                            "PCR[{}] contains all 0xFF bytes. This cannot occur through \
                             normal TPM extend operations and indicates direct manipulation.",
                            idx
                        ),
                    )
                    .with_confidence(0.98)
                    .with_details(serde_json::json!({
                        "pcr_index": idx,
                        "pattern": "all_ones",
                    }))
                    .with_recommendation(
                        "TPM integrity compromised. Hardware inspection required.",
                    ),
                );
            }
        }

        // Check for identical PCR[0-3] (replay attack indicator)
        if let (Some(p0), Some(p1), Some(p2), Some(p3)) = (
            parsed.get(&0),
            parsed.get(&1),
            parsed.get(&2),
            parsed.get(&3),
        ) {
            if p0 == p1 && p1 == p2 && p2 == p3 && !p0.iter().all(|&b| b == 0) {
                findings.push(
                    Finding::new(
                        "pcr_oracle",
                        Severity::Critical,
                        "PCR[0-3] are identical - possible replay attack",
                        "PCR registers 0-3 contain identical non-zero values. \
                         This is statistically impossible under normal measured boot \
                         and strongly suggests a replay or forgery attack.",
                    )
                    .with_confidence(0.95)
                    .with_details(serde_json::json!({
                        "pattern": "identical_pcrs",
                        "value": Self::hex_encode(p0),
                    }))
                    .with_recommendation("Investigate for PCR replay attack or TPM emulation."),
                );
            }
        }

        // Check for sequential byte patterns (forgery)
        for (&idx, val) in &parsed {
            if val.len() >= 4 {
                let is_sequential = val.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
                if is_sequential {
                    findings.push(
                        Finding::new(
                            "pcr_oracle",
                            Severity::High,
                            &format!("PCR[{}] contains sequential bytes - likely forged", idx),
                            &format!(
                                "PCR[{}] contains a sequential byte pattern which cannot \
                                 result from SHA hash operations.",
                                idx
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "pcr_index": idx,
                            "pattern": "sequential",
                        })),
                    );
                }
            }
        }

        findings
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }

    fn find_config_region(data: &[u8]) -> Option<&[u8]> {
        // Look for ACPI RSDP signature as config region marker
        let rsdp_sig = b"RSD PTR ";
        data.windows(8).position(|w| w == rsdp_sig).map(|pos| {
            let end = (pos + 256).min(data.len());
            &data[pos..end]
        })
    }

    fn find_option_roms(data: &[u8]) -> Vec<&[u8]> {
        let mut roms = Vec::new();
        let rom_sig = [0x55u8, 0xAA];
        let mut pos = 0;
        while pos + 3 < data.len() {
            if data[pos] == rom_sig[0] && data[pos + 1] == rom_sig[1] {
                let size = (data[pos + 2] as usize) * 512;
                if size > 0 && pos + size <= data.len() {
                    roms.push(&data[pos..pos + size]);
                    pos += size;
                    continue;
                }
            }
            pos += 512; // Option ROMs are 512-byte aligned
        }
        roms
    }

    fn find_boot_manager(data: &[u8]) -> Option<&[u8]> {
        // Look for Windows Boot Manager signature
        let bootmgr_sig = b"BOOTMGR";
        data.windows(7).position(|w| w == bootmgr_sig).map(|pos| {
            let start = pos.saturating_sub(0x200);
            let end = (pos + 0x10000).min(data.len());
            &data[start..end]
        })
    }

    fn find_secureboot_policy(data: &[u8]) -> Option<&[u8]> {
        // Look for SecureBoot variable (UTF-16LE)
        let sb_var: Vec<u8> = "SecureBoot"
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        data.windows(sb_var.len())
            .position(|w| w == sb_var.as_slice())
            .map(|pos| {
                let end = (pos + 128).min(data.len());
                &data[pos..end]
            })
    }

    fn hex_encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn hex_decode(hex: &str) -> Option<Vec<u8>> {
        if !hex.len().is_multiple_of(2) {
            return None;
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
            .collect()
    }
}

impl Detector for PcrOracleDetector {
    fn name(&self) -> &str {
        "pcr_oracle"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Predict PCR values from firmware content
        let predicted = self.predict_pcrs(&data);

        // Compare against baseline if available
        if let Some(ref baseline) = self.baseline {
            if let Some(ref pcr_values) = baseline.pcr_values {
                // Run anomaly pattern detection
                findings.extend(self.check_anomaly_patterns(pcr_values));

                // Compare predicted vs actual
                for (idx, predicted_val) in &predicted {
                    let idx_str = idx.to_string();
                    if let Some(actual_hex) = pcr_values.get(&idx_str) {
                        let predicted_hex = Self::hex_encode(predicted_val);
                        if predicted_hex != *actual_hex && !actual_hex.is_empty() {
                            findings.push(
                                Finding::new(
                                    "pcr_oracle",
                                    Severity::Critical,
                                    &format!(
                                        "PCR[{}] prediction mismatch - firmware may be tampered",
                                        idx
                                    ),
                                    &format!(
                                        "Oracle predicted PCR[{}] = {} but actual TPM value is {}. \
                                         Firmware content does not match the measured boot state.",
                                        idx, predicted_hex, actual_hex
                                    ),
                                )
                                .with_confidence(0.95)
                                .with_details(serde_json::json!({
                                    "pcr_index": idx,
                                    "predicted": predicted_hex,
                                    "actual": actual_hex,
                                }))
                                .with_recommendation(
                                    "Firmware image differs from what was measured by TPM. \
                                     Investigate for runtime modification or bootkit presence.",
                                ),
                            );
                        }
                    }
                }
            }
        }

        Ok(findings)
    }
}
