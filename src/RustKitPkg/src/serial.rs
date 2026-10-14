//! 16550 UART serial output for range boots.
//!
//! Talks directly to the COM1 port (0x3F8) so RustKit markers appear in
//! the QEMU `-serial` log of the cyber range without any UEFI console
//! negotiation — the same discipline BootkitPkg's range modules use.

const COM1: u16 = 0x3F8;

/// Write one byte to COM1 (busy-wait on the transmitter holding reg).
pub fn putb(b: u8) {
    // Wait for THR empty (LSR bit 5).
    while (inb(COM1 + 5) & 0x20) == 0 {}
    outb(COM1, b);
}

/// Write a byte string.
pub fn write(s: &[u8]) {
    for &b in s {
        putb(b);
    }
}

/// Write a byte string followed by CRLF.
pub fn writeln(s: &[u8]) {
    write(s);
    write(b"\r\n");
}

#[allow(dead_code)]
pub fn outb(port: u16, val: u8) {
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[allow(dead_code)]
pub fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") val,
            in("dx") port,
            options(nomem, nostack, preserves_flags)
        );
    }
    val
}
