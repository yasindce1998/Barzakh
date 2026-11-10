//! C↔Rust CommBuffer confused-deputy model.
//!
//! SMM communication (`EFI_SMM_COMMUNICATE_PROTOCOL`) is the seam where
//! legacy C SMM drivers meet new Rust components: the C side fills a
//! shared buffer in ordinary DRAM, raises an SMI, and the SMM side
//! validates then consumes it. The historic vulnerability class at this
//! seam is the **double fetch** (TOCTOU): the validator reads a length
//! from the buffer, the consumer re-reads it, and an attacker running on
//! another CPU mutates the field between the two reads.
//!
//! This module provides both sides of the research story:
//!
//! * [`validate_vulnerable`] — the classic double-fetch pattern, kept so
//!   the boundary fuzzer and adversary payloads have a live model.
//! * [`validate_hardened`] — the single-copy fix: snapshot the header,
//!   validate the snapshot, consume the snapshot.

/// `EFI_SMM_COMMUNICATE_HEADER`: HeaderGuid (16) + MessageLength (u32) +
/// Message[...]. Header is 20 bytes before the message payload.
pub const COMM_HEADER_LEN: usize = 20;

/// The Barzakh research SMM handler GUID (matches `RUSTKIT_MARKER_GUID`):
/// messages carrying it route to the RustKit SMM handler model.
pub const HANDLER_GUID: [u8; 16] = [
    0x58, 0x5C, 0x6E, 0x9B, 0x1E, 0x8C, 0x5F, 0x4E, 0xB0, 0x7A, 0x2D, 0x3C, 0x4F, 0x5E, 0x6A,
    0x7B,
];

/// Verdict of CommBuffer validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Buffer is safe for the handler to consume (up to the returned length).
    Valid(u32),
    /// Validation failed; carries the reason.
    Invalid(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Shorter than the fixed header.
    TruncatedHeader,
    /// Header GUID does not route to this handler.
    UnknownHandler,
    /// Declared message length exceeds the actual buffer.
    LengthOverrun,
    /// The buffer changed between validation and use (double fetch).
    Toctou,
}

/// VULNERABLE — the classic double-fetch validation.
///
/// `buffer_at_validation` and `buffer_at_use` model the same physical
/// CommBuffer as seen by the validator and (later, on the SMI handler's
/// re-read) by the consumer. When they differ, a real attack is in flight.
/// This function *detects* the mismatch (research oracle) but documents
/// that a production driver doing two fetches would be exploitable: the
/// return value must be treated as untrusted by the consumer.
///
/// Returns [`Reason::Toctou`] when the two views disagree — that is the
/// confused-deputy signal the boundary fuzzer hunts for.
pub fn validate_vulnerable(
    buffer_at_validation: &[u8],
    buffer_at_use: &[u8],
) -> Verdict {
    // First fetch: validate the header snapshot.
    let first = match validate_hardened(buffer_at_validation) {
        Verdict::Valid(n) => n,
        Verdict::Invalid(r) => return Verdict::Invalid(r),
    };
    // Second fetch: re-read the header instead of reusing the snapshot.
    let second = match validate_hardened(buffer_at_use) {
        Verdict::Valid(n) => n,
        Verdict::Invalid(r) => return Verdict::Invalid(r),
    };
    if first != second {
        return Verdict::Invalid(Reason::Toctou);
    }
    Verdict::Valid(first)
}

/// HARDENED — single-copy validation.
///
/// Snapshots nothing across calls: the whole decision is derived from one
/// consistent view, and the returned length is bounded by the *actual*
/// slice length, never by the attacker-controlled field alone.
pub fn validate_hardened(buffer: &[u8]) -> Verdict {
    if buffer.len() < COMM_HEADER_LEN {
        return Verdict::Invalid(Reason::TruncatedHeader);
    }
    if buffer[0..16] != HANDLER_GUID {
        return Verdict::Invalid(Reason::UnknownHandler);
    }
    let declared = u32::from_le_bytes([
        buffer[16],
        buffer[17],
        buffer[18],
        buffer[19],
    ]);
    let available = (buffer.len() - COMM_HEADER_LEN) as u32;
    if declared > available {
        return Verdict::Invalid(Reason::LengthOverrun);
    }
    Verdict::Valid(declared)
}

/// Build a CommBuffer with the given declared message length into `out`
/// (no_std-safe: no allocation). Returns the number of bytes written, or
/// `None` when `out` is too small for header + payload.
pub fn build_into(guid: [u8; 16], declared_len: u32, payload: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = COMM_HEADER_LEN + payload.len();
    if out.len() < total {
        return None;
    }
    out[..16].copy_from_slice(&guid);
    out[16..20].copy_from_slice(&declared_len.to_le_bytes());
    out[COMM_HEADER_LEN..total].copy_from_slice(payload);
    Some(total)
}

/// Allocate-and-build helper for host-side tests and tooling.
#[cfg(test)]
pub fn build(guid: [u8; 16], declared_len: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(COMM_HEADER_LEN + payload.len());
    v.extend_from_slice(&guid);
    v.extend_from_slice(&declared_len.to_le_bytes());
    v.extend_from_slice(payload);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardened_accepts_well_formed() {
        let buf = build(HANDLER_GUID, 4, &[1, 2, 3, 4]);
        assert_eq!(validate_hardened(&buf), Verdict::Valid(4));
    }

    #[test]
    fn hardened_rejects_truncated() {
        assert_eq!(
            validate_hardened(&buf_trunc()),
            Verdict::Invalid(Reason::TruncatedHeader)
        );
    }

    fn buf_trunc() -> Vec<u8> {
        vec![0u8; COMM_HEADER_LEN - 1]
    }

    #[test]
    fn hardened_rejects_unknown_handler() {
        let buf = build([0u8; 16], 4, &[1, 2, 3, 4]);
        assert_eq!(
            validate_hardened(&buf),
            Verdict::Invalid(Reason::UnknownHandler)
        );
    }

    #[test]
    fn hardened_rejects_length_overrun() {
        // Declares 0x1000 bytes of message but carries 4 — the classic
        // confused-deputy overrun the canary allocator must catch when
        // validation is bypassed.
        let buf = build(HANDLER_GUID, 0x1000, &[1, 2, 3, 4]);
        assert_eq!(
            validate_hardened(&buf),
            Verdict::Invalid(Reason::LengthOverrun)
        );
    }

    #[test]
    fn vulnerable_detects_toctou() {
        let before = build(HANDLER_GUID, 4, &[1, 2, 3, 4]);
        // Attacker mutates the declared length between the two fetches —
        // to a still-valid but different value, so both fetches succeed
        // individually and only the mismatch exposes the double fetch.
        let mut after = before.clone();
        after[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            validate_vulnerable(&before, &after),
            Verdict::Invalid(Reason::Toctou)
        );
    }

    #[test]
    fn vulnerable_passes_consistent_views() {
        let buf = build(HANDLER_GUID, 4, &[1, 2, 3, 4]);
        assert_eq!(validate_vulnerable(&buf, &buf), Verdict::Valid(4));
    }
}
