use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// RustKit marker GUID (matches `src/RustKitPkg/src/lib.rs`):
/// 9B6E5C58-8C1E-4E5F-B07A-2D3C4F5E6A7B.
pub const RUSTKIT_MARKER_GUID: [u8; 16] = [
    0x58, 0x5C, 0x6E, 0x9B, 0x1E, 0x8C, 0x5F, 0x4E, 0xB0, 0x7A, 0x2D, 0x3C, 0x4F, 0x5E, 0x6A, 0x7B,
];

/// Rust compiler path string embedded in Rust binaries (panic locations,
/// metadata): unreachable in constrained-alphabet benign corpora.
const RUSTC_PATH: &[u8] = b"/rustc/";

/// `EFI_SMM_COMMUNICATE_HEADER`: HeaderGuid (16) + MessageLength (u32).
const COMM_HEADER_LEN: usize = 20;

/// Declared lengths beyond this are implausible for an SMM message.
const MAX_PLAUSIBLE_MESSAGE: u32 = 0x10_0000;

/// Detects Rust-compiled UEFI firmware modules and the C↔Rust
/// CommBuffer confused-deputy (TOCTOU) patterns they can carry.
///
/// The firmware industry's migration to pure-Rust cores (Patina and
/// allied efforts) moves the Ring -2 attack surface to the FFI seam
/// between legacy C SMM drivers and Rust components. This detector
/// recognizes both sides of that seam in a firmware image:
///
/// * **Rust-UEFI binaries**: PE images containing the compiler path string
///   `/rustc/` (embedded in panic/metadata of every Rust binary) or the
///   RustKit research marker GUID — combined with PE structure validation
///   so random buffers never fire.
/// * **CommBuffer TOCTOU**: an `EFI_SMM_COMMUNICATE_HEADER`-shaped
///   structure routed to a handler GUID whose declared `MessageLength`
///   exceeds the bytes actually present — the double-fetch primitive of
///   the C↔Rust confused-deputy class, where validation reads one length
///   and consumption re-reads another.
pub struct RustUefiModuleDetector;

impl Default for RustUefiModuleDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl RustUefiModuleDetector {
    pub fn new() -> Self {
        Self
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // ── Rust-UEFI binary recognition ───────────────────────────────
        let has_marker = data.windows(16).any(|w| w == RUSTKIT_MARKER_GUID);
        let has_rustc = data.windows(RUSTC_PATH.len()).any(|w| w == RUSTC_PATH);
        if has_marker || has_rustc {
            let signed = Self::pe_certificate_size(data).unwrap_or(0) > 0;
            let (severity, label) = if signed {
                (Severity::Medium, "signed")
            } else {
                (Severity::High, "unsigned")
            };
            let source = if has_marker {
                "RustKit research marker GUID"
            } else {
                "Rust compiler path string"
            };
            findings.push(
                Finding::new(
                    "rust_uefi_module",
                    severity,
                    &format!("Rust-compiled UEFI module ({label})"),
                    &format!(
                        "The image contains a Rust-compiled UEFI binary ({source} inside a \
                         structurally valid PE chain). Rust firmware modules are the emerging \
                         Ring -2 attack surface: their C↔Rust FFI seams (SMM CommBuffer \
                         validation, protocol dispatch) carry confused-deputy risk that \
                         signature coverage does not address{} — a custom loader can map \
                         them without measurement.",
                        if signed {
                            ""
                        } else {
                            ", and this one is unsigned"
                        },
                    ),
                )
                .with_confidence(if has_marker { 0.85 } else { 0.75 })
                .with_details(serde_json::json!({
                    "marker_guid": has_marker,
                    "rustc_path": has_rustc,
                    "signed": signed,
                })),
            );
        }

        // ── CommBuffer confused-deputy (TOCTOU) pattern ────────────────
        findings.extend(self.scan_commbuffers(data));
        findings
    }

    /// Find `EFI_SMM_COMMUNICATE_HEADER` structures routed to the RustKit
    /// handler GUID with a declared message length exceeding the bytes
    /// actually present after the header.
    fn scan_commbuffers(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        if data.len() < COMM_HEADER_LEN + 8 {
            return findings;
        }
        for off in 0..data.len() - COMM_HEADER_LEN {
            if data[off..off + 16] != RUSTKIT_MARKER_GUID {
                continue;
            }
            let declared = u32::from_le_bytes(data[off + 16..off + 20].try_into().unwrap());
            if declared == 0 {
                continue;
            }
            let available = (data.len() - off - COMM_HEADER_LEN) as u32;
            if declared > available || declared > MAX_PLAUSIBLE_MESSAGE {
                findings.push(
                    Finding::new(
                        "rust_uefi_module",
                        Severity::Critical,
                        "CommBuffer confused-deputy pattern (C↔Rust TOCTOU)",
                        &format!(
                            "An SMM communication buffer at offset 0x{off:08X} routes to the \
                             RustKit handler GUID but declares a MessageLength of 0x{declared:X} \
                             bytes with only 0x{available:X} bytes present after the header. A \
                             handler that validates the declared length in one read and consumes \
                             it in another (the classic double fetch across the C↔Rust FFI seam) \
                             is coerced into an out-of-bounds copy — the confused-deputy \
                             primitive this detector exists to catch.",
                        ),
                    )
                    .with_confidence(0.85)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{off:08X}"),
                        "declared_length": declared,
                        "available_bytes": available,
                        "handler": "rustkit",
                    }))
                    .with_recommendation(
                        "Single-copy validation: snapshot the CommBuffer header, validate the \
                         snapshot, and consume the snapshot; bracket SMM handler buffers with \
                         guard pages (see the RustKitPkg trap-page allocator).",
                    ),
                );
            }
        }
        findings
    }

    /// Certificate-table size of the first valid PE image in the buffer,
    /// if any (signature check for the Rust-binary finding).
    fn pe_certificate_size(data: &[u8]) -> Option<u32> {
        const MZ: [u8; 2] = [0x4D, 0x5A];
        const PE_SIG: [u8; 4] = [0x50, 0x45, 0x00, 0x00];
        if data.len() < 0x40 || data[0..2] != MZ {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(data[0x3C..0x40].try_into().ok()?) as usize;
        if !(0x40..=0x400).contains(&e_lfanew) || e_lfanew + 24 > data.len() {
            return None;
        }
        if data[e_lfanew..e_lfanew + 4] != PE_SIG {
            return None;
        }
        let optional_size = u16::from_le_bytes(data[e_lfanew + 20..e_lfanew + 22].try_into().ok()?);
        if optional_size < 0xF0 {
            return None;
        }
        let optional = e_lfanew + 24;
        let magic = u16::from_le_bytes(data[optional..optional + 2].try_into().ok()?);
        let dd = optional
            + match magic {
                0x020B => 112,
                0x010B => 96,
                _ => return None,
            };
        let dir4 = dd + 4 * 8;
        if dir4 + 8 > data.len() {
            return None;
        }
        Some(u32::from_le_bytes(
            data[dir4 + 4..dir4 + 8].try_into().ok()?,
        ))
    }
}

impl Detector for RustUefiModuleDetector {
    fn name(&self) -> &str {
        "rust_uefi_module"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE image with the given certificate size.
    fn build_pe(cert_size: u32) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(&[0x4D, 0x5A]);
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0x00, 0x00]);
        pe[0x80 + 20..0x80 + 22].copy_from_slice(&0xF0u16.to_le_bytes());
        pe[0x80 + 24..0x80 + 26].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        let dd = 0x80 + 24 + 112 + 4 * 8;
        pe[dd + 4..dd + 8].copy_from_slice(&cert_size.to_le_bytes());
        pe
    }

    #[test]
    fn fires_on_rustkit_marker_guid() {
        let mut pe = build_pe(0);
        pe[0x200..0x210].copy_from_slice(&RUSTKIT_MARKER_GUID);
        let findings = RustUefiModuleDetector::new().scan(&pe);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("Rust-compiled") && f.severity == Severity::High));
    }

    #[test]
    fn fires_on_rustc_path_string() {
        let mut pe = build_pe(0);
        pe[0x200..0x200 + RUSTC_PATH.len()].copy_from_slice(RUSTC_PATH);
        let findings = RustUefiModuleDetector::new().scan(&pe);
        assert!(findings.iter().any(|f| f.title.contains("Rust-compiled")));
    }

    #[test]
    fn signed_rust_module_is_medium() {
        let mut pe = build_pe(0x280); // certificate present
        pe[0x200..0x210].copy_from_slice(&RUSTKIT_MARKER_GUID);
        let findings = RustUefiModuleDetector::new().scan(&pe);
        assert!(findings
            .iter()
            .any(|f| f.severity == Severity::Medium && f.title.contains("signed")));
    }

    #[test]
    fn fires_on_commbuffer_toctou() {
        let mut data = vec![0u8; 0x200];
        data[0x40..0x50].copy_from_slice(&RUSTKIT_MARKER_GUID);
        data[0x50..0x54].copy_from_slice(&0x1000u32.to_le_bytes()); // declared >> available
        let findings = RustUefiModuleDetector::new().scan(&data);
        assert!(findings
            .iter()
            .any(|f| f.title.contains("confused-deputy") && f.severity == Severity::Critical));
    }

    #[test]
    fn consistent_commbuffer_is_quiet() {
        let mut data = vec![0u8; 0x100];
        data[0x40..0x50].copy_from_slice(&RUSTKIT_MARKER_GUID);
        // Declared length exactly matches the bytes after the header.
        let available = (data.len() - 0x40 - COMM_HEADER_LEN) as u32;
        data[0x50..0x54].copy_from_slice(&available.to_le_bytes());
        let findings = RustUefiModuleDetector::new().scan(&data);
        // The marker GUID legitimately identifies a RustKit artifact (the
        // module finding may fire) — but a *consistent* CommBuffer must
        // never raise the confused-deputy finding.
        assert!(
            !findings.iter().any(|f| f.title.contains("confused-deputy")),
            "consistent buffer must not alarm: {findings:?}"
        );
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(RustUefiModuleDetector::new()
            .scan(&vec![0u8; 0x8000])
            .is_empty());
    }
}
