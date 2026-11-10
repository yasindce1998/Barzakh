use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Authenticated variable header (UEFI PI): 60 fixed bytes before the name.
const AUTH_VAR_HEADER_LEN: usize = 60;

/// Emits firmware carrying a UEFI variable store (`$VSS`) whose `db`
/// enrollment is *newer* than the `dbx` revocation list, and — critically —
/// no TCG event log recording any `EV_EFI_VARIABLE_*` measurement: the
/// signature of a CVE-2025-3052 / CVE-2024-7344-class silent Secure Boot
/// downgrade performed by a vulnerable signed binary or custom PE loader
/// writing NVRAM directly.
pub struct NvramSilentDowngradePayload;

impl Payload for NvramSilentDowngradePayload {
    fn name(&self) -> &str {
        "nvram_silent_downgrade"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Variable store header at offset 0.
        data[0x00..0x04].copy_from_slice(b"$VSS");
        data[0x04..0x08].copy_from_slice(&0x1000u32.to_le_bytes()); // store size
        data[0x08] = 0x5A; // format: authenticated
        data[0x09] = 0xFE; // state: valid

        // Variable entries: db enrolled 2026-06, dbx frozen at 2024-01 —
        // the revocation list predates the enrollment (downgrade).
        let mut pos = 28usize;
        for (name, year, month) in [("db", 2026u16, 6u8), ("dbx", 2024, 1)] {
            let mut name_utf16 = Vec::new();
            for c in name.chars().chain(std::iter::once('\0')) {
                name_utf16.extend_from_slice(&(c as u16).to_le_bytes());
            }
            let data_size = 128usize;
            let e = &mut data[pos..pos + AUTH_VAR_HEADER_LEN];
            e[0..2].copy_from_slice(&[0x55, 0xAA]); // StartId
            e[2] = 0x3F; // state: valid
            e[36..40].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
            e[40..44].copy_from_slice(&(data_size as u32).to_le_bytes());
            e[16..18].copy_from_slice(&year.to_le_bytes()); // EFI_TIME year
            e[18] = month;
            e[19] = 1; // day
            pos += AUTH_VAR_HEADER_LEN;
            data[pos..pos + name_utf16.len()].copy_from_slice(&name_utf16);
            pos += name_utf16.len();
            while !pos.is_multiple_of(4) {
                data[pos] = 0;
                pos += 1;
            }
            // Variable payload (a forged certificate list body).
            for b in &mut data[pos..pos + data_size] {
                *b = 0xA5;
            }
            pos += data_size;
        }

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "nvram_verifier".to_string(),
            min_severity: Severity::High,
        }]
    }
}
