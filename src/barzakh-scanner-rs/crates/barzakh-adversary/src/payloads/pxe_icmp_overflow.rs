//! Adversary payload for CVE-2026-97631 (GHSA-99cj-7hg9-mp4m): the
//! 16-year-old buffer overflow in EDK II's PXE Base Code driver
//! (NetworkPkg/UefiPxeBcDxe).
//!
//! While a machine PXE-boots, the driver keeps a receive request open for
//! ICMP error messages and copies each one into the fixed 504-byte
//! `Mode.IcmpError` field of `EFI_PXE_BASE_CODE_MODE`. In
//! `PxeBcIcmpErrorDpcHandle` (IPv4) and `PxeBcIcmp6ErrorDpcHandle` (IPv6)
//! the bounds handling is wrong: a message longer than 504 bytes is still
//! copied in full, and the destination pointer advances by the cumulative
//! length rather than the per-fragment length. An unauthenticated network
//! attacker who can deliver ICMP error messages to the PXE-booting target
//! writes attacker-controlled bytes past the field into adjacent DXE-phase
//! memory — the rest of `EFI_PXE_BASE_CODE_MODE` (`TftpErrorReceived`,
//! `EFI_PXE_BASE_CODE_TFTP_ERROR TftpError`, `SetMakeCallback`, ...) and
//! beyond — enabling ring-0 code execution before the OS loads. The
//! advisory notes attackers can forge an event-notification entry (a
//! callback with an attacker-controlled function pointer) to run their
//! code.
//!
//! This payload generates a synthetic post-exploitation DXE memory image
//! containing an `EFI_PXE_BASE_CODE_MODE`-shaped structure whose
//! `IcmpError` field starts with an ICMPv4 error header (Type 3
//! destination-unreachable, embedded IPv4 header beginning with 0x45) and
//! whose attacker data continues past the 504-byte field boundary into
//! the smashed adjacent fields.

use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Size of `EFI_PXE_BASE_CODE_MODE.IcmpError`
/// (`EFI_PXE_BASE_CODE_MAX_ICMP_EXT_DATA_LEN` in EDK II MdePkg).
const PXE_ICMP_ERROR_SIZE: usize = 504;

/// Offset of the `IcmpError` field inside the synthetic mode structure.
const ICMP_ERROR_OFF: usize = 0x480;

/// Bytes the armed variant writes past the field boundary — into the
/// smashed `TftpErrorReceived` / `TftpError` / `SetMakeCallback` region.
const OVERFLOW_LEN: usize = 0x100;

/// Recognizable attacker fill repeated through the oversized ICMP error
/// message body and the smashed adjacent fields.
const ATTACKER_MARKER: u64 = 0xBAAD_F00D_C0DE_BEEF;

/// Foreign function pointer of the forged event-notification entry — a
/// canonical far (userspace-style) address no DXE-phase allocation ever
/// produces.
const FAKE_EVENT_NOTIFY_FN: u64 = 0x0000_6000_C0DE_0000;

/// `gEfiEventReadyToBootGuid` in EDK II mixed-endian byte order — the
/// event group of the forged notification entry.
const EFI_EVENT_GUID: [u8; 16] = [
    0xB3, 0x8F, 0xE7, 0x7C, 0xD7, 0x4B, 0x79, 0x46, 0x87, 0xA8, 0xA8, 0xD8, 0xDE, 0xE5, 0x0D, 0x2B,
];

pub struct PxeIcmpOverflowPayload;

impl Payload for PxeIcmpOverflowPayload {
    fn name(&self) -> &str {
        "pxe_icmp_overflow"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // EFI_PXE_BASE_CODE_MODE BOOLEAN prefix: Started, Ipv6Available,
        // Ipv6Supported, UsingIpv6, BisSupported, BisDetected, AutoArp,
        // SendGUID, DhcpDiscoverValid, DhcpAckReceived,
        // ProxyOfferReceived, PxeDiscoverValid, PxeReplyReceived,
        // PxeBisReplyReceived, IcmpErrorReceived, TftpErrorReceived.
        let flags: [u8; 16] = [
            1, 0, 1, 0, // Started, Ipv6Available, Ipv6Supported, UsingIpv6
            0, 0, 1, 0, // BisSupported, BisDetected, AutoArp, SendGUID
            1, 1, 0,
            1, // DhcpDiscoverValid, DhcpAckReceived, ProxyOfferReceived, PxeDiscoverValid
            1, 0, 1,
            0, // PxeReplyReceived, PxeBisReplyReceived, IcmpErrorReceived, TftpErrorReceived
        ];
        data[0x400..0x410].copy_from_slice(&flags);

        // The ICMPv4 error message the vulnerable `PxeBcIcmpErrorDpcHandle`
        // copies into `Mode.IcmpError`: Type 3 (destination unreachable),
        // Code 1, checksum, 4 unused bytes, then the embedded IPv4 header
        // of the offending packet (0x45 = version 4, IHL 5).
        let icmp = &mut data[ICMP_ERROR_OFF..];
        icmp[0] = 3;
        icmp[1] = 1;
        icmp[2] = 0x1E;
        icmp[3] = 0x0F;
        // icmp[4..8] unused — already zero.
        // Embedded IPv4 header: TOS 0, total length 1500, id 1, no
        // fragmentation, TTL 64, protocol UDP, checksum, 10.0.0.1 ->
        // 10.0.0.2.
        let ipv4: [u8; 20] = [
            0x45, 0x00, 0x05, 0xDC, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x6E, 0x1F, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02,
        ];
        icmp[8..28].copy_from_slice(&ipv4);
        // First 8 bytes of the original datagram (UDP header, PXE ports).
        let udp: [u8; 8] = [0x08, 0x16, 0x08, 0x16, 0x00, 0x08, 0xA1, 0xB2];
        icmp[28..36].copy_from_slice(&udp);
        // 4 bytes of original-datagram payload ("PXE!").
        icmp[36..40].copy_from_slice(b"PXE!");

        if config.dormant {
            // Kill-switched variant: the ICMP error is well-formed and
            // fits WITHIN the 504-byte field (64-byte error, rest of the
            // field zeroed). The adjacent mode fields are intact —
            // TftpErrorReceived clear, no forged event entry — the
            // implant never armed; detectors must stay quiet.
            icmp[40..64].copy_from_slice(&[0u8; 24]);
            return Ok(data);
        }

        // Armed variant: the attacker-controlled message body continues
        // through the rest of the field and PAST the 504-byte boundary
        // into the adjacent mode fields — CVE-2026-97631 copies the
        // message in full without length-checking it against the field.
        let boundary = ICMP_ERROR_OFF + PXE_ICMP_ERROR_SIZE;
        let fill_end = boundary + OVERFLOW_LEN;
        let mut off = ICMP_ERROR_OFF + 40;
        while off + 8 <= fill_end {
            data[off..off + 8].copy_from_slice(&ATTACKER_MARKER.to_le_bytes());
            off += 8;
        }

        // Smashed adjacent structure: the `TftpErrorReceived` flag is
        // forced non-zero, then a forged event-notification entry (a
        // foreign function pointer, EVT_NOTIFY_SIGNAL type, notify
        // context cookie, and an EFI_EVENT GUID) rides in the smashed
        // `TftpError` / `SetMakeCallback` region.
        data[boundary] = 1;
        let entry = boundary + 8;
        data[entry..entry + 8].copy_from_slice(&FAKE_EVENT_NOTIFY_FN.to_le_bytes());
        data[entry + 8..entry + 12].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        data[entry + 12..entry + 16].copy_from_slice(&[0xAB, 0xAD, 0xFA, 0xCE]);
        data[entry + 16..entry + 32].copy_from_slice(&EFI_EVENT_GUID);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "pxe_icmp_overflow".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate(dormant: bool) -> Vec<u8> {
        PxeIcmpOverflowPayload
            .generate(&PayloadConfig {
                dormant,
                ..Default::default()
            })
            .unwrap()
    }

    #[test]
    fn armed_overflow_extends_past_field_boundary() {
        let data = generate(false);
        let boundary = ICMP_ERROR_OFF + PXE_ICMP_ERROR_SIZE;

        // ICMPv4 error header: Type 3 destination-unreachable, then the
        // embedded IPv4 header beginning with 0x45.
        assert_eq!(data[ICMP_ERROR_OFF], 3);
        assert_eq!(data[ICMP_ERROR_OFF + 1], 1);
        assert_eq!(data[ICMP_ERROR_OFF + 8], 0x45);
        assert_eq!(&data[ICMP_ERROR_OFF + 17..ICMP_ERROR_OFF + 18], &[0x11]);

        // The attacker data fills the whole field and continues past the
        // 504-byte boundary into the adjacent fields.
        assert!(data[ICMP_ERROR_OFF..boundary].iter().any(|&b| b != 0));
        assert!(data[boundary..boundary + OVERFLOW_LEN]
            .iter()
            .any(|&b| b != 0));

        // Smashed TftpErrorReceived flag.
        assert_eq!(data[boundary], 1);

        // Forged event-notification entry: foreign function pointer plus
        // an EFI_EVENT GUID in the smashed adjacent region.
        assert!(data
            .windows(8)
            .any(|w| w == FAKE_EVENT_NOTIFY_FN.to_le_bytes()));
        assert!(data.windows(16).any(|w| w == EFI_EVENT_GUID));

        // Repeated attacker marker fill inside the overflow.
        assert_eq!(
            data[boundary + 0x30..boundary + 0x38],
            ATTACKER_MARKER.to_le_bytes()
        );
    }

    #[test]
    fn dormant_error_fits_inside_field() {
        let data = generate(true);
        let boundary = ICMP_ERROR_OFF + PXE_ICMP_ERROR_SIZE;

        // Well-formed 64-byte ICMP error ...
        assert_eq!(data[ICMP_ERROR_OFF], 3);
        assert_eq!(data[ICMP_ERROR_OFF + 8], 0x45);
        assert!(data[ICMP_ERROR_OFF..ICMP_ERROR_OFF + 64]
            .iter()
            .any(|&b| b != 0));

        // ... entirely within the field: the rest of the 504-byte
        // IcmpError field is zeroed.
        assert!(data[ICMP_ERROR_OFF + 64..boundary].iter().all(|&b| b == 0));

        // Adjacent fields intact: TftpErrorReceived clear, no smashed
        // region, no forged event, no attacker marker anywhere.
        assert_eq!(data[boundary], 0);
        assert!(data[boundary..boundary + OVERFLOW_LEN]
            .iter()
            .all(|&b| b == 0));
        assert!(!data.windows(8).any(|w| w == ATTACKER_MARKER.to_le_bytes()));
        assert!(!data
            .windows(8)
            .any(|w| w == FAKE_EVENT_NOTIFY_FN.to_le_bytes()));
        assert!(!data.windows(16).any(|w| w == EFI_EVENT_GUID));
    }

    #[test]
    fn payload_is_deterministic() {
        let a = generate(false);
        let b = generate(false);
        assert_eq!(a, b);
    }
}
