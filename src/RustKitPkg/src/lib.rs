//! Barzakh RustKitPkg — pure-Rust `no_std` UEFI research modules.
//!
//! The firmware industry is migrating from C/EDK II toward pure-Rust cores
//! (Patina and allied efforts). The Ring -2 vulnerability class shifts from
//! buffer overflows to **FFI and confused-deputy boundaries** between legacy
//! C SMM drivers and Rust components. RustKitPkg owns the offensive *and*
//! defensive research tooling for that boundary:
//!
//! * [`commbuffer`] — the C↔Rust CommBuffer confused-deputy model: a
//!   *vulnerable* double-fetch validation (for adversary modeling and
//!   boundary fuzzing) and a *hardened* single-copy validation.
//! * [`canary`] — the SMRAM canary & trap-page allocator: guard pages
//!   around SMM save-state structures that catch CommBuffer overruns
//!   *before* `RIP`/`CR3` corruption, logging the fault to a protected page.
//! * [`mode`] — the kill-switch discipline (simulation-first, research
//!   gate, time-bomb, air-gap), mirroring BootkitPkg's `BarzakhMode.h`.
//! * [`serial`] — 16550 UART output so range boots (OVMF + `-serial`)
//!   produce visible markers.
//!
//! ## Build & test
//!
//! ```text
//! cargo test                                     # host unit tests (std)
//! cargo build --release --target x86_64-unknown-uefi   # firmware image
//! ```
//!
//! The resulting `target/x86_64-unknown-uefi/release/librustkit.so`... no —
//! the cdylib output *is* the EFI application image; rename/copy it as
//! `EFI/BOOT/BOOTX64.EFI` on a FAT ESP to boot it in range OVMF.
//!
//! ## Safety
//!
//! Everything here is SIMULATION-ONLY by default: no flash writes, no real
//! SMRAM manipulation, no SMI generation. The functional path is gated
//! behind `--features functional` which itself requires `barzakh_research`
//! (compile-time error otherwise), a time-bomb, and an air-gap check.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), deny(unsafe_op_in_unsafe_fn))]

pub mod canary;
pub mod commbuffer;
pub mod dxe;
pub mod mode;
#[cfg(all(target_arch = "x86_64", not(test)))]
pub mod serial;

/// RustKit module marker GUID (little-endian byte form):
/// 9B6E5C58-8C1E-4E5F-B07A-2D3C4F5E6A7B.
///
/// Embedded in every RustKit image so the Barzakh scanner can recognize
/// Rust-UEFI research modules (`rust_uefi_module` detector).
pub const RUSTKIT_MARKER_GUID: [u8; 16] = [
    0x58, 0x5C, 0x6E, 0x9B, 0x1E, 0x8C, 0x5F, 0x4E, 0xB0, 0x7A, 0x2D, 0x3C, 0x4F, 0x5E, 0x6A,
    0x7B,
];

/// ASCII rendering of the marker, for serial banners and documentation.
pub const RUSTKIT_BANNER: &[u8] = b"BARZAKH-RUSTKIT";
