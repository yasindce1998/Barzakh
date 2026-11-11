//! Detector for CVE-2026-97631 (GHSA-99cj-7hg9-mp4m): a 16-year-old
//! buffer overflow in EDK II's PXE Base Code driver
//! (NetworkPkg/UefiPxeBcDxe).
//!
//! While a machine PXE-boots, the driver keeps a receive request open for
//! ICMP error messages and copies each one into the fixed 504-byte
//! `Mode.IcmpError` field of `EFI_PXE_BASE_CODE_MODE`. The bounds
//! handling in `PxeBcIcmpErrorDpcHandle` / `PxeBcIcmp6ErrorDpcHandle` is
//! wrong: a message longer than 504 bytes is still copied in full, and
//! the destination pointer advances by the cumulative rather than the
//! per-fragment length. An unauthenticated network attacker who can
//! deliver ICMP error messages to the PXE-booting target writes
//! attacker-controlled bytes past the field into adjacent DXE-phase
//! memory — the rest of `EFI_PXE_BASE_CODE_MODE` (`TftpErrorReceived`,
//! `EFI_PXE_BASE_CODE_TFTP_ERROR TftpError`, `SetMakeCallback`, ...) and
//! beyond — enabling arbitrary ring-0 code execution before the OS loads
//! and before Secure Boot / measured boot verify anything. The advisory
//! notes attackers can forge an event-notification entry (a callback
//! with an attacker-controlled function pointer) to run their code.
//!
//! The detector works structurally on raw bytes at any offset. It fires
//! only when ALL of the following hold:
//!
//! 1. an ICMPv4 error header (Type 3/11/12, zero unused bytes, non-zero
//!    checksum) is followed by an embedded IPv4 header with version
//!    nibble 4, IHL >= 5, a plausible protocol (ICMP/TCP/UDP) and a
//!    plausible total length;
//! 2. a sustained attacker-data run (>= 90% non-zero) extends BEYOND the
//!    504-byte `EFI_PXE_BASE_CODE_MODE.IcmpError` field size — the
//!    oversized-copy signature of the CVE;
//! 3. past the field boundary, the run either smashes the adjacent mode
//!    structure (>= 90% non-zero where the benign
//!    `TftpErrorReceived`/`TftpError`/`SetMakeCallback` region is
//!    NUL-padded) or carries a fake-event signature: a far canonical
//!    pointer no DXE-phase allocation produces, a known EFI event-group
//!    GUID, or a repeated 8-byte attacker fill marker.

use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// Size of `EFI_PXE_BASE_CODE_MODE.IcmpError`
/// (`EFI_PXE_BASE_CODE_MAX_ICMP_EXT_DATA_LEN` in EDK II MdePkg).
const PXE_ICMP_ERROR_SIZE: usize = 504;

/// Minimum sustained continuation past the ICMP header start before the
/// copy is considered oversized: the field size plus 64 bytes of smash.
const MIN_CONTINUATION: usize = PXE_ICMP_ERROR_SIZE + 64;

/// Past-boundary window inspected for smashed adjacent mode fields
/// (`TftpErrorReceived`, `EFI_PXE_BASE_CODE_TFTP_ERROR`, `SetMakeCallback`).
const SMASH_WINDOW: usize = 160;

/// Past-boundary window inspected for fake-event signatures.
const FAKE_EVENT_WINDOW: usize = 256;

/// Non-zero density threshold classifying a region as a sustained
/// attacker-data run (benign mode fields are NUL-padded).
const RUN_DENSITY: f64 = 0.90;

/// Lower/upper bounds of the "foreign far pointer" range: canonical
/// low-half addresses at or above 2^46 are never legitimate DXE-phase
/// firmware/heap pointers, which live below 4 GB.
const FAR_PTR_MIN: u64 = 0x0000_4000_0000_0000;
const FAR_PTR_MAX: u64 = 0x0000_8000_0000_0000;

/// Minimum repetitions of an 8-byte value that classify a repeated
/// attacker fill marker.
const MIN_MARKER_REPS: usize = 4;

/// EFI event-group GUIDs (EDK II mixed-endian byte order) used by forged
/// event-notification entries: `gEfiEventReadyToBootGuid` and
/// `gEfiEventExitBootServicesGuid`.
const EFI_EVENT_GUIDS: [&[u8]; 2] = [
    // gEfiEventReadyToBootGuid {7CE88FB3-4BD7-4679-87A8-A8D8DEE50D2B}
    &[
        0xB3, 0x8F, 0xE7, 0x7C, 0xD7, 0x4B, 0x79, 0x46, 0x87, 0xA8, 0xA8, 0xD8, 0xDE, 0xE5, 0x0D,
        0x2B,
    ],
    // gEfiEventExitBootServicesGuid {27ABF055-B1B8-4C26-8048-748F0BFDF91E}
    &[
        0x55, 0xF0, 0xAB, 0x27, 0xB8, 0xB1, 0x26, 0x4C, 0x80, 0x48, 0x74, 0x8F, 0x0B, 0xFD, 0xF9,
        0x1E,
    ],
];

/// Bound on reported findings per image.
const MAX_FINDINGS: usize = 8;

pub struct PxeIcmpOverflowDetector;

impl Default for PxeIcmpOverflowDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl PxeIcmpOverflowDetector {
    pub fn new() -> Self {
        Self
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        if data.len() < MIN_CONTINUATION {
            return findings;
        }

        for i in 0..data.len() {
            if !Self::is_icmp_error_header(data, i) {
                continue;
            }
            let boundary = i + PXE_ICMP_ERROR_SIZE;
            if boundary + SMASH_WINDOW > data.len() {
                continue;
            }
            // A sustained attacker-data run must extend past the
            // 504-byte IcmpError field: the oversized-copy signature.
            if !Self::sustained_run(data, i) {
                continue;
            }
            let smashed = Self::smashed_adjacent(data, boundary);
            let fake_event = Self::fake_event_signature(data, boundary);
            if !smashed && !fake_event {
                continue;
            }

            findings.push(
                Finding::new(
                    "pxe_icmp_overflow",
                    Severity::Critical,
                    "PXE Base Code ICMP error buffer overflow (CVE-2026-97631)",
                    &format!(
                        "An ICMPv4 error header at offset 0x{:08X} is followed by a sustained \
                         attacker-data run extending past the 504-byte \
                         EFI_PXE_BASE_CODE_MODE.IcmpError field into the adjacent mode \
                         structure{} This is CVE-2026-97631 / GHSA-99cj-7hg9-mp4m: EDK II's \
                         PXE Base Code driver (NetworkPkg/UefiPxeBcDxe) copies oversized ICMP \
                         error messages into the fixed IcmpError field while a machine \
                         PXE-boots, so an unauthenticated network attacker can overwrite \
                         DXE-phase memory and — via a forged event-notification entry — \
                         execute ring-0 code before Secure Boot and measured boot verify \
                         anything.",
                        i,
                        if fake_event {
                            ", carrying a forged event-notification signature."
                        } else {
                            ", smashing the TftpError/SetMakeCallback region."
                        }
                    ),
                )
                .with_confidence(0.90)
                .with_details(serde_json::json!({
                    "offset": format!("0x{:08X}", i),
                    "icmp_type": data[i],
                    "field_size": PXE_ICMP_ERROR_SIZE,
                    "smashed_adjacent": smashed,
                    "fake_event": fake_event,
                    "cve": "CVE-2026-97631",
                    "ghsa": "GHSA-99cj-7hg9-mp4m",
                }))
                .with_recommendation(
                    "Update EDK II / vendor firmware to a build carrying the \
                     NetworkPkg/UefiPxeBcDxe ICMP error bounds fix (CVE-2026-97631); disable \
                     network/PXE boot on machines that do not need it.",
                ),
            );
            if findings.len() >= MAX_FINDINGS {
                break;
            }
        }

        findings
    }

    /// Structural gate: an ICMPv4 error header (Type 3 destination
    /// unreachable, 11 time exceeded, or 12 parameter problem) whose
    /// unused bytes are zero (RFC 792) and whose checksum is non-zero,
    /// followed by the embedded IPv4 header of the offending packet with
    /// version nibble 4, IHL >= 5, a plausible protocol (ICMP/TCP/UDP)
    /// and a plausible MTU-bounded total length.
    fn is_icmp_error_header(data: &[u8], i: usize) -> bool {
        if i + 20 > data.len() {
            return false;
        }
        if !matches!(data[i], 3 | 11 | 12) {
            return false;
        }
        if data[i + 2] == 0 && data[i + 3] == 0 {
            return false;
        }
        if data[i + 4..i + 8] != [0u8; 4] {
            return false;
        }
        let version_ihl = data[i + 8];
        if version_ihl & 0xF0 != 0x40 || version_ihl & 0x0F < 5 {
            return false;
        }
        if !matches!(data[i + 17], 1 | 6 | 17) {
            return false;
        }
        let total_length = u16::from_be_bytes([data[i + 10], data[i + 11]]);
        (28..=1500).contains(&total_length)
    }

    /// Non-zero byte density of a region.
    fn non_zero_density(region: &[u8]) -> f64 {
        if region.is_empty() {
            return 0.0;
        }
        let non_zero = region.iter().filter(|&&b| b != 0).count();
        non_zero as f64 / region.len() as f64
    }

    /// A sustained attacker-data run (>= 90% non-zero) of at least
    /// [`MIN_CONTINUATION`] bytes from the ICMP header start: the
    /// oversized ICMP error message itself.
    fn sustained_run(data: &[u8], start: usize) -> bool {
        let end = start + MIN_CONTINUATION;
        if end > data.len() {
            return false;
        }
        Self::non_zero_density(&data[start..end]) >= RUN_DENSITY
    }

    /// The benign mode structure past `IcmpError` (`TftpErrorReceived`,
    /// `EFI_PXE_BASE_CODE_TFTP_ERROR` with its NUL-padded `ErrorString`,
    /// `SetMakeCallback`) is zero-dominated; a >= 90% non-zero window
    /// right past the 504-byte field boundary is the smashed-adjacent
    /// signature. Smashed structure data is varied (flags, pointers,
    /// GUIDs); a window of a single repeated byte is ordinary firmware
    /// padding (0x00/0xFF erase-state fill), not a smash.
    fn smashed_adjacent(data: &[u8], boundary: usize) -> bool {
        let end = boundary + SMASH_WINDOW;
        if end > data.len() {
            return false;
        }
        let window = &data[boundary..end];
        if Self::non_zero_density(window) < RUN_DENSITY {
            return false;
        }
        let mut distinct = [false; 256];
        let mut distinct_count = 0usize;
        for &b in window {
            if !distinct[b as usize] {
                distinct[b as usize] = true;
                distinct_count += 1;
            }
        }
        distinct_count >= 4
    }

    /// Fake-event signature inside the overflow region: a far canonical
    /// pointer no DXE-phase allocation produces, a known EFI event-group
    /// GUID, or a repeated 8-byte attacker fill marker.
    fn fake_event_signature(data: &[u8], boundary: usize) -> bool {
        let end = (boundary + FAKE_EVENT_WINDOW).min(data.len());
        if boundary + 8 > end {
            return false;
        }
        let window = &data[boundary..end];

        // Foreign far pointer at any offset.
        for j in 0..=window.len() - 8 {
            let value = u64::from_le_bytes(window[j..j + 8].try_into().unwrap_or([0; 8]));
            if (FAR_PTR_MIN..FAR_PTR_MAX).contains(&value) {
                return true;
            }
        }

        // Known EFI event-group GUID.
        for guid in EFI_EVENT_GUIDS {
            if window.windows(16).any(|w| *w == *guid) {
                return true;
            }
        }

        // Repeated 8-byte attacker fill marker (skip zero and all-0xFF
        // padding runs, which are ordinary firmware fill).
        let mut counts = std::collections::HashMap::new();
        let (chunks, _) = window.as_chunks::<8>();
        for chunk in chunks {
            let value = u64::from_le_bytes(*chunk);
            if value == 0 || value == u64::MAX {
                continue;
            }
            let count = counts.entry(value).or_insert(0usize);
            *count += 1;
            if *count >= MIN_MARKER_REPS {
                return true;
            }
        }

        false
    }
}

impl Detector for PxeIcmpOverflowDetector {
    fn name(&self) -> &str {
        "pxe_icmp_overflow"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICMP_ERROR_SIZE: usize = 504;
    const ATTACKER_MARKER: u64 = 0xBAAD_F00D_C0DE_BEEF;
    const FAKE_EVENT_NOTIFY_FN: u64 = 0x0000_6000_C0DE_0000;

    /// Well-formed ICMPv4 error header + embedded IPv4/UDP headers, as
    /// the PXE Base Code driver receives it.
    fn write_icmp_error(buf: &mut [u8]) {
        buf[0] = 3; // Type: destination unreachable
        buf[1] = 1; // Code: host unreachable
        buf[2] = 0x1E;
        buf[3] = 0x0F; // checksum (non-zero)
                       // buf[4..8] unused — zero
        let ipv4: [u8; 20] = [
            0x45, 0x00, 0x05, 0xDC, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x6E, 0x1F, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02,
        ];
        buf[8..28].copy_from_slice(&ipv4);
        let udp: [u8; 8] = [0x08, 0x16, 0x08, 0x16, 0x00, 0x08, 0xA1, 0xB2];
        buf[28..36].copy_from_slice(&udp);
        buf[36..40].copy_from_slice(b"PXE!");
    }

    /// Armed overflow: ICMP error header at 0x480, attacker marker fill
    /// through the field and past the boundary, smashed TftpErrorReceived
    /// flag and a forged event-notification entry in the adjacent region
    /// (mirrors the `pxe_icmp_overflow` adversary payload).
    fn armed_image() -> Vec<u8> {
        let icmp_off = 0x480;
        let boundary = icmp_off + ICMP_ERROR_SIZE;
        let mut data = vec![0u8; 0x2000];
        write_icmp_error(&mut data[icmp_off..]);
        let fill_end = boundary + 0x100;
        let mut off = icmp_off + 40;
        while off + 8 <= fill_end {
            data[off..off + 8].copy_from_slice(&ATTACKER_MARKER.to_le_bytes());
            off += 8;
        }
        data[boundary] = 1;
        let entry = boundary + 8;
        data[entry..entry + 8].copy_from_slice(&FAKE_EVENT_NOTIFY_FN.to_le_bytes());
        data[entry + 8..entry + 12].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        data[entry + 12..entry + 16].copy_from_slice(&[0xAB, 0xAD, 0xFA, 0xCE]);
        data[entry + 16..entry + 32].copy_from_slice(EFI_EVENT_GUIDS[0]);
        data
    }

    /// Dormant (kill-switched) image: a well-formed 64-byte ICMP error
    /// that fits within the field; adjacent mode fields intact.
    fn dormant_image() -> Vec<u8> {
        let icmp_off = 0x480;
        let mut data = vec![0u8; 0x2000];
        write_icmp_error(&mut data[icmp_off..]);
        data[icmp_off + 40..icmp_off + 64].copy_from_slice(&[0u8; 24]);
        data
    }

    #[test]
    fn fires_on_armed_overflow() {
        let findings = PxeIcmpOverflowDetector::new().scan(&armed_image());
        assert!(findings.iter().any(|f| f.severity == Severity::Critical),);
        let f = findings
            .iter()
            .find(|f| f.severity == Severity::Critical)
            .unwrap();
        assert_eq!(f.detector, "pxe_icmp_overflow");
        assert!(f.description.contains("CVE-2026-97631"));
        assert!(f.description.contains("GHSA-99cj-7hg9-mp4m"));
    }

    #[test]
    fn quiet_on_dormant_variant() {
        assert!(PxeIcmpOverflowDetector::new()
            .scan(&dormant_image())
            .is_empty());
    }

    #[test]
    fn quiet_on_plain_short_icmp_error() {
        // A plain 64-byte ICMP error on its own: no overflow, no smash.
        let mut data = vec![0u8; 0x2000];
        write_icmp_error(&mut data[0x100..]);
        data[40..64].copy_from_slice(&[0u8; 24]);
        assert!(PxeIcmpOverflowDetector::new().scan(&data).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(PxeIcmpOverflowDetector::new()
            .scan(&vec![0u8; 0x2000])
            .is_empty());
    }

    #[test]
    fn quiet_on_uniform_firmware_fill_after_icmp_error() {
        // A well-formed ICMP error followed by ordinary 0xFF firmware
        // padding: the padding is dense enough to look like a sustained
        // run, but it is uniform erase-state fill, not smashed varied
        // structure data, and carries no fake-event signature.
        let mut data = vec![0xFFu8; 0x2000];
        write_icmp_error(&mut data[0x100..]);
        // The ICMP error header's unused bytes must be zero for the
        // header to be well-formed (write_icmp_error leaves them).
        data[0x104..0x108].fill(0);
        assert!(PxeIcmpOverflowDetector::new().scan(&data).is_empty());
    }

    #[test]
    fn quiet_on_noise_after_short_error() {
        // A well-formed short (64-byte) ICMP error inside the field with
        // unrelated dense noise starting only past the 504-byte boundary:
        // no oversized message was copied, so the sustained-run check
        // must keep the detector quiet even though the adjacent memory
        // is non-zero.
        let mut data = vec![0u8; 0x2000];
        let icmp_off = 0x100;
        write_icmp_error(&mut data[icmp_off..]);
        data[icmp_off + 40..icmp_off + 64].copy_from_slice(&[0u8; 24]);
        for (i, b) in data.iter_mut().enumerate().skip(icmp_off + ICMP_ERROR_SIZE) {
            *b = (i as u64)
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407) as u8;
        }
        assert!(PxeIcmpOverflowDetector::new().scan(&data).is_empty());
    }
}
