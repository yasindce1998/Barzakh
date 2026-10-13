pub mod corpus;
pub mod deploy;
pub mod harness;
pub mod payloads;
pub mod robustness;
pub mod scenario;
pub mod validate;

use anyhow::Result;
use barzakh_core::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X86_64,
    Aarch64,
    RiscV64,
    /// IBM POWER / OpenPOWER (OPAL, skiboot)
    Power64,
    /// 32-bit ARM (automotive ECUs, IoT microcontrollers)
    Armv7,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadConfig {
    pub arch: Arch,
    pub size: usize,
}

impl Default for PayloadConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            size: 0x10000,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFinding {
    pub detector: String,
    pub min_severity: Severity,
}

pub trait Payload: Send + Sync {
    fn name(&self) -> &str;
    fn arch(&self) -> Arch;
    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>>;
    fn expected_detections(&self) -> Vec<ExpectedFinding>;
}

pub use payloads::create_all_payloads;
