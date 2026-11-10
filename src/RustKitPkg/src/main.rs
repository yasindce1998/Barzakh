//! RustKit DXE firmware image (`rustkit-dxe`).
//!
//! Freestanding UEFI application following the `x86_64-unknown-uefi`
//! contract: export `efi_main`, provide a panic handler, link nothing but
//! `core`. All logic lives in the `rustkit` library (`dxe::run`) so it is
//! unit-testable on the host; this file is the thin firmware shell.

#![no_main]
#![no_std]

use core::ffi::c_void;

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    // A UEFI application runs in the firmware's address space: halting is
    // the safe failure mode (never unwind through firmware stacks).
    loop {}
}

#[export_name = "efi_main"]
pub extern "C" fn main(image: *mut c_void, st: *mut c_void) -> usize {
    // SAFETY: the firmware entry-point contract guarantees a valid system
    // table pointer (or, defensively, null — `run` handles that).
    unsafe {
        rustkit::dxe::run(
            image as r_efi::base::Handle,
            st as *mut r_efi::system::SystemTable,
        )
    }
}
