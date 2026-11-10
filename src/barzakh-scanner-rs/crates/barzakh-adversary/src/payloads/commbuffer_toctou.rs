use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// RustKit handler GUID (matches `src/RustKitPkg/src/commbuffer.rs` and
/// the `rust_uefi_module` detector):
/// 9B6E5C58-8C1E-4E5F-B07A-2D3C4F5E6A7B.
const HANDLER_GUID: [u8; 16] = [
    0x58, 0x5C, 0x6E, 0x9B, 0x1E, 0x8C, 0x5F, 0x4E, 0xB0, 0x7A, 0x2D, 0x3C, 0x4F, 0x5E, 0x6A, 0x7B,
];

/// `EFI_SMM_COMMUNICATE_HEADER`: HeaderGuid (16) + MessageLength (u32).
const COMM_HEADER_LEN: usize = 20;

/// Emits firmware modeling the C↔Rust **CommBuffer confused-deputy
/// (TOCTOU)** pattern: an SMM communication buffer routed to the RustKit
/// handler GUID whose declared `MessageLength` (0x1000) far exceeds the
/// bytes actually present (64). A handler that validates the declared
/// length in one read and consumes it in another — the classic double
/// fetch across the FFI seam — is coerced into an out-of-bounds copy.
///
/// This is the boundary-fuzzer-discovered pattern codified as a detection
/// rule (`rust_uefi_module`, "CommBuffer confused-deputy pattern"); the
/// defensive counterpart is the RustKitPkg trap-page allocator that
/// catches the overrun before `RIP`/`CR3` corruption.
pub struct CommbufferToctouPayload;

impl Payload for CommbufferToctouPayload {
    fn name(&self) -> &str {
        "commbuffer_toctou"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // SMM communication buffer at offset 0x100.
        const COMM_OFF: usize = 0x100;
        data[COMM_OFF..COMM_OFF + 16].copy_from_slice(&HANDLER_GUID);
        // Declared message length: 2 MiB — beyond any plausible SMM
        // message and beyond the bytes present, whatever the image size.
        data[COMM_OFF + 16..COMM_OFF + 20].copy_from_slice(&0x20_0000u32.to_le_bytes());
        // ...but only 64 bytes of message actually follow the header.
        let msg = &mut data[COMM_OFF + COMM_HEADER_LEN..COMM_OFF + COMM_HEADER_LEN + 64];
        put(b"DOUBLEFETCH", &mut msg[0x00..0x10]);
        put(b"C-to-Rust-FFI", &mut msg[0x10..0x20]);
        msg[0x20..0x40].fill(0xE7);

        // A second, *shrinking* buffer at 0x400: the mutation an attacker
        // applies between the validator's fetch and the consumer's fetch
        // (declared 0x40 with 16 present — a length that changes under
        // the handler's feet).
        const MUT_OFF: usize = 0x400;
        data[MUT_OFF..MUT_OFF + 16].copy_from_slice(&HANDLER_GUID);
        data[MUT_OFF + 16..MUT_OFF + 20].copy_from_slice(&0x40u32.to_le_bytes());

        // Rust binary surface so the module context is visible too.
        put(b"/rustc/9b3d25b16a1e9f2b4d3e", &mut data[0x800..0x820]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "rust_uefi_module".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}

/// Copy `s` into `dest` (padded with zeros), tolerating length mismatch.
fn put(s: &[u8], dest: &mut [u8]) {
    let n = s.len().min(dest.len());
    dest[..n].copy_from_slice(&s[..n]);
}
