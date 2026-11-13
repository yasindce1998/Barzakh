use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::detector::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum HashAlgorithm {
    Sha1 = 0x0004,
    Sha256 = 0x000B,
}

impl HashAlgorithm {
    pub fn digest_size(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                // sha1 0.11 implements digest 0.11's `Digest` trait, which is
                // distinct from the digest 0.10 trait re-exported by sha2.
                use sha1::Digest as _;
                let mut hasher = Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Self::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }
}

pub struct PcrReplayEngine {
    algorithm: HashAlgorithm,
    pcr_banks: HashMap<u8, Vec<u8>>,
}

impl Default for PcrReplayEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PcrReplayEngine {
    pub fn new() -> Self {
        Self::with_algorithm(HashAlgorithm::Sha256)
    }

    pub fn with_algorithm(algorithm: HashAlgorithm) -> Self {
        let mut pcr_banks = HashMap::new();
        for i in 0..24 {
            pcr_banks.insert(i, vec![0u8; algorithm.digest_size()]);
        }
        Self {
            algorithm,
            pcr_banks,
        }
    }

    pub fn reset(&mut self) {
        for pcr in self.pcr_banks.values_mut() {
            pcr.fill(0);
        }
    }

    pub fn extend(&mut self, pcr_index: u8, digest: &[u8]) {
        if let Some(current) = self.pcr_banks.get(&pcr_index) {
            let mut data = current.clone();
            data.extend_from_slice(digest);
            let new_value = self.algorithm.hash(&data);
            self.pcr_banks.insert(pcr_index, new_value);
        }
    }

    pub fn get_pcr(&self, index: u8) -> Option<&[u8]> {
        self.pcr_banks.get(&index).map(|v| v.as_slice())
    }

    pub fn replay_event_log(&mut self, events: &[EventLogEntry]) -> HashMap<u8, Vec<u8>> {
        self.reset();
        for event in events {
            if event.pcr_index < 24 {
                let digest = self.algorithm.hash(&event.event_data);
                self.extend(event.pcr_index, &digest);
            }
        }
        self.pcr_banks.clone()
    }

    pub fn validate_against_tpm(
        &self,
        tpm_pcrs: &HashMap<u8, Vec<u8>>,
        pcr_range: (u8, u8),
    ) -> Vec<Finding> {
        let mut findings = Vec::new();

        for index in pcr_range.0..pcr_range.1 {
            if let (Some(replayed), Some(actual)) =
                (self.pcr_banks.get(&index), tpm_pcrs.get(&index))
            {
                if replayed != actual {
                    findings.push(
                        Finding::new(
                            "pcr",
                            Severity::Critical,
                            &format!(
                                "PCR {} replay mismatch - possible event log tampering",
                                index
                            ),
                            &format!(
                                "Replayed PCR {} value does not match TPM value. \
                                 Expected (from replay): {}, Actual (from TPM): {}. \
                                 This strongly indicates the event log has been tampered with.",
                                index,
                                hex::encode(replayed),
                                hex::encode(actual),
                            ),
                        )
                        .with_details(serde_json::json!({
                            "pcr_index": index,
                            "replayed": hex::encode(replayed),
                            "actual": hex::encode(actual),
                        }))
                        .with_recommendation(
                            "Event log integrity compromised. Investigate for bootkit presence.",
                        ),
                    );
                }
            }
        }

        findings
    }
}

#[derive(Debug, Clone)]
pub struct EventLogEntry {
    pub pcr_index: u8,
    pub event_type: u32,
    pub event_data: Vec<u8>,
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
