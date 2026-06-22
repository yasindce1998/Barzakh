use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SmmTimingAnomalyPayload;

impl Payload for SmmTimingAnomalyPayload {
    fn name(&self) -> &str {
        "smm_timing_anomaly"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // At offset 0x100: TSEG base pattern — address 0x7F800000 (8 bytes LE)
        // followed by mask value with lock bit CLEAR (0xFFF00000 without bit 0 set)
        let offset = 0x100;
        let tseg_base: u64 = 0x7F800000;
        data[offset..offset + 8].copy_from_slice(&tseg_base.to_le_bytes());
        let mask_no_lock: u32 = 0xFFF00000; // lock bit (bit 0) is CLEAR
        data[offset + 8..offset + 12].copy_from_slice(&mask_no_lock.to_le_bytes());

        // At offset 0x200: SMI handler code pattern
        // INT3 (0xCC) repeated 4 times, then JMP far (0xEA + address), then RSM (0x0F 0xAA)
        let offset = 0x200;
        data[offset] = 0xCC; // INT3
        data[offset + 1] = 0xCC; // INT3
        data[offset + 2] = 0xCC; // INT3
        data[offset + 3] = 0xCC; // INT3
        data[offset + 4] = 0xEA; // JMP far
        data[offset + 5] = 0x00; // address bytes
        data[offset + 6] = 0x00;
        data[offset + 7] = 0x80;
        data[offset + 8] = 0x7F;
        data[offset + 9] = 0x00;
        data[offset + 10] = 0x0F; // RSM instruction
        data[offset + 11] = 0xAA;

        // At offset 0x400: SMM Save State Map pattern
        // Processor state (RIP, RSP, RFLAGS) at known offsets from a base
        // that's NOT in SMRAM range (indicating manipulation)
        let offset = 0x400;
        // RIP at offset +0x00 — address outside SMRAM
        let rip: u64 = 0x0000_0000_DEAD_C0DE;
        data[offset..offset + 8].copy_from_slice(&rip.to_le_bytes());
        // RSP at offset +0x08 — address outside SMRAM
        let rsp: u64 = 0x0000_0000_BAAD_F00D;
        data[offset + 8..offset + 16].copy_from_slice(&rsp.to_le_bytes());
        // RFLAGS at offset +0x10
        let rflags: u64 = 0x0000_0000_0000_0246;
        data[offset + 16..offset + 24].copy_from_slice(&rflags.to_le_bytes());

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "smm_timing".to_string(),
            min_severity: Severity::High,
        }]
    }
}
