use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ClkscrewVoltagePayload;

impl Payload for ClkscrewVoltagePayload {
    fn name(&self) -> &str {
        "clkscrew_voltage"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0x00u8; size];

        // Generate CLKscrew/DVFS manipulation pattern.
        // The voltage_glitch detector check_dvfs_manipulation looks for:
        //   ARM PMIC I2C address bytes: 0x60 or 0x62 followed by a register byte <= 0x7F
        //   and a non-zero value byte (PMIC voltage regulator write via I2C bus).

        // Place PMIC I2C voltage regulator write bursts. The voltage_glitch
        // detector requires a burst: >= 4 transactions to the same PMIC I2C
        // address within 128 bytes, with value bytes inside a narrow band —
        // the signature of nudging a voltage operating point (CLKscrew).
        let pmic_sequences = [
            // Burst 1: PMIC addr 0x60, voltage ramp 0xA0 -> 0xB8
            (0x200, 0x60u8, 0x10u8, 0xA0u8),
            (0x210, 0x60, 0x11, 0xA8),
            (0x220, 0x60, 0x12, 0xB0),
            (0x230, 0x60, 0x13, 0xB8),
            // Burst 2: PMIC addr 0x62 (alternate), ramp 0x50 -> 0x68
            (0x280, 0x62, 0x20, 0x50),
            (0x290, 0x62, 0x21, 0x58),
            (0x2A0, 0x62, 0x22, 0x60),
            (0x2B0, 0x62, 0x23, 0x68),
        ];

        for &(offset, addr, reg, val) in &pmic_sequences {
            if offset + 3 < size {
                data[offset] = addr;
                data[offset + 1] = reg;
                data[offset + 2] = val;
            }
        }

        // Also place x86 DVFS pattern: WRMSR with MSR 0x199 (IA32_PERF_CTL)
        // to show cross-platform voltage attack
        let x86_base = 0x1000;
        // MOV ECX, 0x199
        data[x86_base] = 0xB9;
        data[x86_base + 1] = 0x99;
        data[x86_base + 2] = 0x01;
        data[x86_base + 3] = 0x00;
        data[x86_base + 4] = 0x00;
        // WRMSR
        data[x86_base + 5] = 0x0F;
        data[x86_base + 6] = 0x30;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "voltage_glitch".to_string(),
            min_severity: Severity::High,
        }]
    }
}
