use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct BasebandRtosHookPayload;

impl Payload for BasebandRtosHookPayload {
    fn name(&self) -> &str {
        "baseband_rtos_hook"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // ARM interrupt vector table: first 32 bytes are branch entries.
        // Entry 0 is a hooked far branch (B with target ~0x60008, well
        // outside the normal vector range) jumping to the implant.
        data[0..4].copy_from_slice(&[0x00, 0x80, 0x01, 0xEA]);

        // ThreadX RTOS marker (after the vector table entries in use)
        data[4..20].copy_from_slice(b"ThreadX_BB_RTOS\x00");

        // Interrupt Vector Table with hooked entry
        // IVT starts at 0x00 in ARM; place a hook that jumps to implant
        let ivt_off = 0x20;
        // LDR PC, [PC, #24] — branches to address stored 24 bytes ahead
        data[ivt_off..ivt_off + 4].copy_from_slice(&[0x18, 0xF0, 0x9F, 0xE5]);
        // Target address for hook (points into implant zone)
        let hook_target = 0x400u32;
        data[ivt_off + 28..ivt_off + 32].copy_from_slice(&hook_target.to_le_bytes());

        // Suspicious task name indicating implant
        let task_off = 0x300;
        let task_str = b"hook_isr_task\x00";
        data[task_off..task_off + task_str.len()].copy_from_slice(task_str);

        // Implant code zone
        let implant_off = 0x400;
        for (j, byte) in data[implant_off..(implant_off + 128).min(size)]
            .iter_mut()
            .enumerate()
        {
            *byte = (((implant_off + j) * 13 + 7) & 0xFF) as u8;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "baseband_rtos".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
