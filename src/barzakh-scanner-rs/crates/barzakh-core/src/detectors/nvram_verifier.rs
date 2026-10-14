use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// NVRAM & Measured Boot verifier — cross-checks live/image UEFI variable
/// state against the TPM 2.0 measurement log. The CVE-2025-3052 /
/// CVE-2024-7344 class of Secure Boot bypasses achieves *silent* downgrades:
/// a vulnerable signed UEFI binary (or custom PE loader) writes `db`/`dbx`
/// directly to NVRAM without the write being measured into `PCR[7]` as an
/// `EV_EFI_VARIABLE_DRIVER_AUTH` event.
///
/// The detector walks an authenticated UEFI variable store (`$VSS`) and:
///
/// * flags Secure Boot variables (`db`, `dbx`, `PK`, `KEK`) that exist with
///   no corresponding `EV_EFI_VARIABLE_*` event anywhere in the TCG log
///   region of the image — an unmeasured write, and
/// * flags `dbx` with an *older* EFI_TIME timestamp than `db` — a revocation
///   list rollback (downgrade).
pub struct NvramVerifierDetector;

impl Default for NvramVerifierDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// Authenticated variable header (UEFI PI): fixed 60 bytes before the name.
const AUTH_VAR_HEADER_LEN: usize = 60;
const VAR_START_ID: [u8; 2] = [0x55, 0xAA];

// TCG event types (little-endian u32 markers) for measured UEFI variable
// writes. Their absence alongside a populated $VSS store is the signal.
const EV_EFI_VARIABLE_DRIVER_AUTH: u32 = 0x8000_00E0;
const EV_EFI_VARIABLE_BOOT: u32 = 0x8000_00E1;
const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E2;

/// A parsed authenticated variable entry.
struct AuthVar {
    #[allow(dead_code)]
    state: u8,
    /// EFI_TIME year+month+day+hour+minute+second packed for comparison.
    timestamp: (u16, u8, u8, u8, u8, u8),
    name: String,
}

impl NvramVerifierDetector {
    pub fn new() -> Self {
        Self
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (off, window) in data.windows(4).enumerate() {
            if window == b"$VSS" {
                findings.extend(self.check_store(data, off));
            }
        }
        findings
    }

    /// Walk authenticated variable entries following a `$VSS` store header.
    fn parse_vars(data: &[u8], store_off: usize) -> Vec<AuthVar> {
        let mut vars = Vec::new();
        // Skip the 28-byte VARIABLE_STORE_HEADER.
        let mut pos = store_off + 28;
        while pos + AUTH_VAR_HEADER_LEN <= data.len() {
            if data[pos..pos + 2] != VAR_START_ID {
                // Variable stores end at the first non-entry; entries are
                // contiguous so there is no need to resynchronize.
                break;
            }
            let state = data[pos + 2];
            let name_size =
                u32::from_le_bytes(data[pos + 36..pos + 40].try_into().unwrap()) as usize;
            let data_size =
                u32::from_le_bytes(data[pos + 40..pos + 44].try_into().unwrap()) as usize;
            // Plausibility bounds: variable names are short, payloads bounded.
            if name_size == 0 || name_size > 256 || data_size > 0x10_0000 {
                break;
            }
            let name_off = pos + AUTH_VAR_HEADER_LEN;
            if name_off + name_size > data.len() {
                break;
            }
            let name: String = data[name_off..name_off + name_size]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes([c[0], c[1]]) as u8 as char)
                .filter(|c| c.is_ascii_graphic() || *c == ' ')
                .collect();
            let ts = &data[pos + 16..pos + 32];
            let timestamp = (
                u16::from_le_bytes([ts[0], ts[1]]),
                ts[2],
                ts[3],
                ts[4],
                ts[5],
                ts[6],
            );
            vars.push(AuthVar {
                state,
                timestamp,
                name,
            });
            // Advance past name (4-byte aligned) + data.
            let entry_len =
                AUTH_VAR_HEADER_LEN + name_size.div_ceil(4) * 4 + data_size.div_ceil(4) * 4;
            pos += entry_len.max(4);
        }
        vars
    }

    fn check_store(&self, data: &[u8], off: usize) -> Vec<Finding> {
        let vars = Self::parse_vars(data, off);
        if vars.is_empty() {
            return Vec::new();
        }
        let mut findings = Vec::new();

        let secure_boot_vars: Vec<&AuthVar> = vars
            .iter()
            .filter(|v| matches!(v.name.as_str(), "db" | "dbx" | "PK" | "KEK"))
            .collect();
        if secure_boot_vars.is_empty() {
            return findings;
        }
        let names: Vec<&str> = secure_boot_vars.iter().map(|v| v.name.as_str()).collect();

        // Cross-check: every Secure Boot variable write must appear in the
        // TCG event log as an EV_EFI_VARIABLE_* measurement.
        let has_var_events = data.windows(4).any(|w| {
            let t = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
            t == EV_EFI_VARIABLE_DRIVER_AUTH
                || t == EV_EFI_VARIABLE_BOOT
                || t == EV_EFI_VARIABLE_AUTHORITY
        });
        if !has_var_events {
            findings.push(
                Finding::new(
                    "nvram_verifier",
                    Severity::Critical,
                    "Unmeasured Secure Boot variable write (silent downgrade)",
                    &format!(
                        "An authenticated UEFI variable store at offset 0x{off:08X} defines \
                         the Secure Boot variables [{}], but the image contains no \
                         EV_EFI_VARIABLE_DRIVER_AUTH / EV_EFI_VARIABLE_BOOT / \
                         EV_EFI_VARIABLE_AUTHORITY events — no TCG log anywhere records these \
                         writes being measured into PCR[7]. This is the signature of the \
                         CVE-2025-3052 / CVE-2024-7344 class of bypasses: a vulnerable \
                         signed UEFI binary or custom PE loader mutating NVRAM directly, so \
                         the TPM attestation stays clean while the boot policy changes.",
                        names.join(", "),
                    ),
                )
                .with_confidence(0.85)
                .with_details(serde_json::json!({
                    "store_offset": format!("0x{off:08X}"),
                    "variables": names,
                    "expected_event_types": [
                        format!("0x{EV_EFI_VARIABLE_DRIVER_AUTH:08X}"),
                        format!("0x{EV_EFI_VARIABLE_BOOT:08X}"),
                        format!("0x{EV_EFI_VARIABLE_AUTHORITY:08X}"),
                    ],
                }))
                .with_recommendation(
                    "Compare the variable store against a golden baseline, re-enroll PK/KEK/db \
                     from vendor media, and re-measure the platform (TPM clear + re-provision) \
                     before trusting attestation.",
                ),
            );
        }

        // Downgrade check: dbx must not predate db.
        let db = vars.iter().find(|v| v.name == "db");
        let dbx = vars.iter().find(|v| v.name == "dbx");
        if let (Some(db), Some(dbx)) = (db, dbx) {
            if dbx.timestamp < db.timestamp {
                findings.push(
                    Finding::new(
                        "nvram_verifier",
                        Severity::High,
                        "dbx revocation list older than db — Secure Boot downgrade",
                        &format!(
                            "In the variable store at offset 0x{off:08X}, the dbx revocation \
                             list timestamp ({:?}) predates the db enrollment timestamp \
                             ({:?}). A revocation list that is older than the database it \
                             revokes from means known-bad certificates remain trusted — the \
                             NVRAM state machine has been rolled back.",
                            dbx.timestamp, db.timestamp,
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "store_offset": format!("0x{off:08X}"),
                        "db_timestamp": format!("{:?}", db.timestamp),
                        "dbx_timestamp": format!("{:?}", dbx.timestamp),
                    })),
                );
            }
        }
        findings
    }
}

impl Detector for NvramVerifierDetector {
    fn name(&self) -> &str {
        "nvram_verifier"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `$VSS` store containing the given (name, year) variables.
    fn store_with_vars(vars: &[(&str, u16)]) -> Vec<u8> {
        let mut s = vec![0u8; 28];
        s[0..4].copy_from_slice(b"$VSS");
        s[4..8].copy_from_slice(&0x1000u32.to_le_bytes()); // store size
        s[8] = 0x5A; // format: authenticated
        s[9] = 0xFE; // state: valid
        for (name, year) in vars {
            let mut name_utf16 = Vec::new();
            for c in name.chars().chain(std::iter::once('\0')) {
                name_utf16.extend_from_slice(&(c as u16).to_le_bytes());
            }
            let data_size = 64usize;
            let mut e = vec![0u8; AUTH_VAR_HEADER_LEN];
            e[0..2].copy_from_slice(&VAR_START_ID);
            e[2] = 0x3F; // state: valid
            e[36..40].copy_from_slice(&(name_utf16.len() as u32).to_le_bytes());
            e[40..44].copy_from_slice(&(data_size as u32).to_le_bytes());
            // EFI_TIME at +16
            e[16..18].copy_from_slice(&year.to_le_bytes());
            e[18] = 6; // month
            e[19] = 1; // day
            s.extend_from_slice(&e);
            s.extend_from_slice(&name_utf16);
            // Pad the name to 4-byte alignment, as the variable walker expects.
            while !s.len().is_multiple_of(4) {
                s.push(0);
            }
            s.extend_from_slice(&vec![0x41u8; data_size]);
        }
        s
    }

    #[test]
    fn fires_on_unmeasured_db_write() {
        let data = store_with_vars(&[("db", 2026), ("dbx", 2026)]);
        let findings = NvramVerifierDetector::new().scan(&data);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Unmeasured") && f.severity == Severity::Critical));
    }

    #[test]
    fn fires_on_dbx_older_than_db() {
        let data = store_with_vars(&[("db", 2026), ("dbx", 2024)]);
        let findings = NvramVerifierDetector::new().scan(&data);
        assert!(findings.iter().any(|f| f.title.contains("older than db")));
    }

    #[test]
    fn quiet_when_events_present() {
        let mut data = store_with_vars(&[("db", 2026), ("dbx", 2026)]);
        // Append a TCG event carrying an EV_EFI_VARIABLE_DRIVER_AUTH type.
        data.extend_from_slice(&EV_EFI_VARIABLE_DRIVER_AUTH.to_le_bytes());
        data.extend_from_slice(&[0u8; 32]);
        let findings = NvramVerifierDetector::new().scan(&data);
        assert!(
            findings.is_empty(),
            "measured writes must not alarm: {findings:?}"
        );
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(NvramVerifierDetector::new()
            .scan(&vec![0u8; 0x8000])
            .is_empty());
    }
}
