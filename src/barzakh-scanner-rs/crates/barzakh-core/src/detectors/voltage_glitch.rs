use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

// MSR 0x150 — Intel OC Mailbox (Plundervolt voltage manipulation)
// Little-endian u16 representation of 0x0150
const MSR_OC_MAILBOX_LO: u8 = 0x50;
#[allow(dead_code)]
const MSR_OC_MAILBOX_HI: u8 = 0x01;

// MSR 0x199 — IA32_PERF_CTL (DVFS frequency/voltage control)
// Little-endian u16 representation of 0x0199
#[allow(dead_code)]
const MSR_PERF_CTL_LO: u8 = 0x99;

// x86 WRMSR opcode (documented for reference; bytes are matched inline for position context)
#[allow(dead_code)]
const WRMSR: &[u8] = &[0x0F, 0x30];

/// `MOV ECX, imm32` opcode — the canonical way MSR addresses reach ECX
/// before WRMSR. Requiring the full `B9 <msr-lo> <msr-hi> 00 00` load
/// (instead of any `50 01` byte pair nearby) keeps ordinary WRMSR-heavy
/// firmware code from matching: random byte pairs are ubiquitous, the
/// 5-byte immediate load for a specific MSR is not.
const MOV_ECX_IMM32: u8 = 0xB9;
const MSR_IMM_HIGH: u8 = 0x01;
const MSR_IMM_PAD: u8 = 0x00;

// SGX instructions
const ENCLS: &[u8] = &[0x0F, 0x01, 0xCF];
const ENCLU: &[u8] = &[0x0F, 0x01, 0xD7];

// Common ARM PMIC I2C addresses (CLKscrew)
const PMIC_I2C_ADDR_60: u8 = 0x60;
const PMIC_I2C_ADDR_62: u8 = 0x62;

/// PMIC transactions must cluster within this window to form a burst.
const PMIC_BURST_WINDOW: usize = 128;
/// Minimum transactions per burst.
const PMIC_BURST_MIN_TRANSACTIONS: usize = 4;
/// Value bytes within a burst must stay inside this band (small nudges
/// around an operating point, not unrelated scattered writes).
const PMIC_VALUE_BAND: u8 = 0x40;

// Maximum negative voltage offset representable in the OC Mailbox payload
// Values with the high byte >= 0xF8 in a 16-bit signed representation indicate
// large negative offsets (more than ~31 mV below nominal), which exceed safe ranges.
const UNSAFE_VOLTAGE_OFFSET_THRESHOLD: u8 = 0xF8;

pub struct VoltageGlitchDetector;

impl Default for VoltageGlitchDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl VoltageGlitchDetector {
    pub fn new() -> Self {
        Self
    }

    /// True when the bytes preceding a WRMSR at `wrmsr_off` contain the
    /// canonical `MOV ECX, <msr>` immediate load (`B9 lo 01 00 00` for
    /// MSRs below 0x10000). Real MSR-writing code loads the address this
    /// way; requiring it separates genuine MSR-targeted WRMSRs from the
    /// sea of unrelated WRMSRs in ordinary firmware code.
    fn has_msr_load(&self, data: &[u8], wrmsr_off: usize, msr_lo: u8) -> bool {
        let scan_start = wrmsr_off.saturating_sub(16);
        let pre = &data[scan_start..wrmsr_off];
        pre.windows(5).any(|w| {
            w[0] == MOV_ECX_IMM32
                && w[1] == msr_lo
                && w[2] == MSR_IMM_HIGH
                && w[3] == MSR_IMM_PAD
                && w[4] == MSR_IMM_PAD
        })
    }

    /// Detect MSR 0x150 (OC Mailbox) writes via WRMSR — Plundervolt voltage manipulation.
    /// Also flags occurrences where the voltage offset encoded in the payload exceeds safe ranges.
    fn check_plundervolt_msr(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        for i in 0..data.len().saturating_sub(1) {
            // Look for WRMSR (0F 30)
            if data[i] != 0x0F || data[i + 1] != 0x30 {
                continue;
            }

            // Require the canonical `MOV ECX, 0x150` load before the WRMSR
            let has_msr_150 = self.has_msr_load(data, i, MSR_OC_MAILBOX_LO);

            if !has_msr_150 {
                continue;
            }

            // Check whether the voltage offset bytes (appearing after the MSR address load)
            // represent a large negative offset (potential unsafe undervolt).
            let scan_start = i.saturating_sub(16);
            let pre_wrmsr = &data[scan_start..i];
            let unsafe_offset = pre_wrmsr
                .windows(2)
                .any(|w| w[1] >= UNSAFE_VOLTAGE_OFFSET_THRESHOLD);

            let severity = if unsafe_offset {
                Severity::Critical
            } else {
                Severity::High
            };

            let description = if unsafe_offset {
                format!(
                    "WRMSR targeting MSR 0x150 (OC Mailbox) at offset 0x{:08X} with a voltage \
                     payload whose high byte indicates a large negative offset (>= 0xF8xx). \
                     This is the characteristic Plundervolt pattern for inducing computational \
                     faults in the CPU core.",
                    i
                )
            } else {
                format!(
                    "WRMSR targeting MSR 0x150 (OC Mailbox) at offset 0x{:08X}. Voltage \
                     manipulation via the OC Mailbox is the mechanism used by Plundervolt \
                     (CVE-2019-11157) to fault SGX enclaves.",
                    i
                )
            };

            findings.push(
                Finding::new(
                    "voltage_glitch",
                    severity,
                    "Plundervolt OC Mailbox MSR write detected",
                    &description,
                )
                .with_confidence(if unsafe_offset { 0.91 } else { 0.78 })
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "msr": "0x150 (IA32_OC_MAILBOX)",
                    "unsafe_offset": unsafe_offset,
                    "technique": "Plundervolt / CVE-2019-11157",
                }))
                .with_recommendation(
                    "Disable OC Mailbox MSR access in production firmware. Apply Intel \
                     microcode update for CVE-2019-11157. Enforce SGX platform quoting \
                     with voltage-attack attestation.",
                ),
            );
        }

        findings
    }

    /// Detect voltage manipulation (MSR 0x150 + WRMSR) within 256 bytes of SGX instructions
    /// (ENCLS / ENCLU). Voltage manipulation near SGX enclaves is the hallmark Plundervolt attack.
    fn check_sgx_voltage_targeting(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Collect all offsets where MSR 0x150 WRMSR pairs occur
        let mut wrmsr_offsets: Vec<usize> = Vec::new();
        for i in 0..data.len().saturating_sub(1) {
            if data[i] == 0x0F
                && data[i + 1] == 0x30
                && self.has_msr_load(data, i, MSR_OC_MAILBOX_LO)
            {
                wrmsr_offsets.push(i);
            }
        }

        if wrmsr_offsets.is_empty() {
            return findings;
        }

        // Search for ENCLS / ENCLU instructions
        for i in 0..data.len().saturating_sub(2) {
            let is_encls = data[i..].starts_with(ENCLS);
            let is_enclu = data[i..].starts_with(ENCLU);
            if !is_encls && !is_enclu {
                continue;
            }

            let instr_name = if is_encls { "ENCLS" } else { "ENCLU" };

            // Check whether any WRMSR(0x150) is within 256 bytes of this SGX instruction
            for &wrmsr_off in &wrmsr_offsets {
                let distance = wrmsr_off.abs_diff(i);

                if distance <= 256 {
                    findings.push(
                        Finding::new(
                            "voltage_glitch",
                            Severity::Critical,
                            "SGX voltage targeting — Plundervolt attack pattern",
                            &format!(
                                "{} instruction at offset 0x{:08X} is within {} bytes of an MSR \
                                 0x150 (OC Mailbox) WRMSR at offset 0x{:08X}. This is the \
                                 definitive Plundervolt (CVE-2019-11157) attack pattern: \
                                 undervolt applied immediately before/after enclave execution \
                                 to induce silent data corruption inside the SGX enclave.",
                                instr_name, i, distance, wrmsr_off
                            ),
                        )
                        .with_confidence(0.94)
                        .with_details(serde_json::json!({
                            "sgx_instruction": instr_name,
                            "sgx_offset": format!("0x{:08X}", i),
                            "wrmsr_offset": format!("0x{:08X}", wrmsr_off),
                            "proximity_bytes": distance,
                            "msr": "0x150 (IA32_OC_MAILBOX)",
                            "technique": "Plundervolt SGX targeting / CVE-2019-11157",
                        }))
                        .with_recommendation(
                            "Apply Intel microcode updates for CVE-2019-11157. Disable OC \
                             Mailbox MSR writes in firmware. Review SGX enclave sealing and \
                             attestation for any indication of tampered measurements.",
                        ),
                    );
                    // One finding per SGX instruction — avoid duplicate reports
                    break;
                }
            }
        }

        findings
    }

    /// Detect DVFS manipulation: MSR 0x199 (IA32_PERF_CTL) writes with extreme values,
    /// and I2C PMIC register write patterns (CLKscrew-style ARM attacks).
    fn check_dvfs_manipulation(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // --- x86: MSR 0x199 (IA32_PERF_CTL) WRMSR ---
        for i in 0..data.len().saturating_sub(1) {
            if data[i] != 0x0F || data[i + 1] != 0x30 {
                continue;
            }

            // Require the canonical `MOV ECX, 0x199` load before the WRMSR
            let has_msr_199 = self.has_msr_load(data, i, MSR_PERF_CTL_LO);

            if !has_msr_199 {
                continue;
            }

            let scan_start = i.saturating_sub(16);
            let pre_wrmsr = &data[scan_start..i];

            // Extreme frequency ratio values: bytes directly after the MSR address load
            // that represent a P-state ratio above 0x3F (63) or below 0x08 are suspicious.
            let extreme_freq = pre_wrmsr.iter().any(|&b| b > 0x3F && b < 0xFF);

            findings.push(
                Finding::new(
                    "voltage_glitch",
                    Severity::High,
                    "IA32_PERF_CTL DVFS manipulation detected",
                    &format!(
                        "WRMSR targeting MSR 0x199 (IA32_PERF_CTL) at offset 0x{:08X}{}. \
                         Manipulating this MSR can drive CPU frequency outside validated \
                         operating ranges, causing transient faults (CLKscrew-style attack \
                         on x86 DVFS).",
                        i,
                        if extreme_freq {
                            " with extreme frequency ratio payload"
                        } else {
                            ""
                        }
                    ),
                )
                .with_confidence(if extreme_freq { 0.82 } else { 0.65 })
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "msr": "0x199 (IA32_PERF_CTL)",
                    "extreme_freq_value": extreme_freq,
                    "technique": "DVFS fault injection / CLKscrew x86 variant",
                }))
                .with_recommendation(
                    "Restrict P-state MSR writes to trusted kernel code. Validate \
                     frequency/voltage operating points against CPU specifications.",
                ),
            );
        }

        // --- ARM: I2C PMIC write patterns (CLKscrew) ---
        // A bare (addr, reg, val) byte triple matches constantly in real
        // firmware volumes, so a finding requires a *burst*: several PMIC
        // transactions to the same I2C address within a short window, with
        // value bytes confined to a narrow band — the signature of an
        // attacker nudging a voltage operating point, not of scattered
        // bytes.
        let pmic_transactions: Vec<(usize, u8, u8)> = (0..data.len().saturating_sub(3))
            .filter(|&i| {
                let addr = data[i];
                let reg = data[i + 1];
                let val = data[i + 2];
                (addr == PMIC_I2C_ADDR_60 || addr == PMIC_I2C_ADDR_62) && reg <= 0x7F && val != 0x00
            })
            .map(|i| (i, data[i], data[i + 2]))
            .collect();

        let mut i = 0;
        while i < pmic_transactions.len() {
            let (base_off, addr, _val) = pmic_transactions[i];
            // Gather the run of transactions to the same address within the
            // burst window.
            let mut j = i;
            let mut vals: Vec<u8> = Vec::new();
            while j < pmic_transactions.len() {
                let (off, a, v) = pmic_transactions[j];
                if a != addr || off - base_off > PMIC_BURST_WINDOW {
                    break;
                }
                vals.push(v);
                j += 1;
            }

            if vals.len() >= PMIC_BURST_MIN_TRANSACTIONS {
                let band = *vals.iter().max().unwrap() as u16 - *vals.iter().min().unwrap() as u16;
                // A CLKscrew-style attack *ramps* the operating point: the
                // value bytes step monotonically in one direction. Random
                // bytes that pass the burst/band gates are not ordered.
                let monotonic =
                    vals.windows(2).all(|w| w[0] < w[1]) || vals.windows(2).all(|w| w[0] > w[1]);
                if band <= PMIC_VALUE_BAND as u16 && monotonic {
                    findings.push(
                        Finding::new(
                            "voltage_glitch",
                            Severity::High,
                            "ARM PMIC I2C voltage/frequency register write burst (CLKscrew pattern)",
                            &format!(
                                "{} PMIC I2C transactions to address 0x{:02X} within {} bytes \
                                 (starting at offset 0x{:08X}) with values in a 0x{:02X}-wide \
                                 band. This matches the CLKscrew ARM DVFS attack pattern where \
                                 voltage or frequency is nudged via I2C to the PMIC to induce \
                                 transient faults.",
                                vals.len(), addr, PMIC_BURST_WINDOW, base_off, PMIC_VALUE_BAND
                            ),
                        )
                        .with_confidence(0.70)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", base_off),
                            "pmic_i2c_address": format!("0x{:02X}", addr),
                            "transactions": vals.len(),
                            "value_band": format!("0x{:02X}", band),
                            "technique": "CLKscrew ARM DVFS / PMIC I2C manipulation",
                        }))
                        .with_recommendation(
                            "Audit PMIC I2C access control. Restrict kernel drivers from \
                             performing arbitrary PMIC register writes. Validate DVFS operating \
                             points against SoC safety margins.",
                        ),
                    );
                    i = j;
                    continue;
                }
            }
            i += 1;
        }

        findings
    }
}

impl Detector for VoltageGlitchDetector {
    fn name(&self) -> &str {
        "voltage_glitch"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_plundervolt_msr(&data));
        findings.extend(self.check_sgx_voltage_targeting(&data));
        findings.extend(self.check_dvfs_manipulation(&data));

        Ok(findings)
    }
}
