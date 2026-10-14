//! RustKit DXE firmware entry point — boots inside range OVMF.
//!
//! The logic here is compiled into the `rustkit-dxe` bin target
//! (`src/main.rs`, `--features firmware`), whose PE image the firmware
//! loads from `EFI/BOOT/BOOTX64.EFI` on a FAT ESP. Everything the module
//! does is simulation-first and kill-switch gated (`crate::mode`):
//!
//! 1. banner marker `BARZAKH-RUSTKIT-BOOTED` to serial (range proof),
//! 2. boot-gate check: time-bomb + air-gap (network protocol presence),
//! 3. CommBuffer confused-deputy **self-test**: a hardened-validation
//!    rejection demo, a TOCTOU oracle detection, then a canary-guarded
//!    copy that deliberately overruns using the attacker-declared
//!    length — the trap-page allocator catches it, the fault is logged
//!    to the protected log page, and the handler *survives* (returns an
//!    error status; the module continues and exits cleanly).

use crate::canary::{ProtectedLog, TrapPageAllocator, GUARD_SIZE};
use crate::commbuffer::{self, Reason, Verdict};
use crate::mode::{self, Gate};

/// Serial output exists only in real firmware builds (host tests stub it
/// out — port I/O would fault).
#[cfg(all(target_arch = "x86_64", not(test)))]
use crate::serial;

/// Serial marker emitted once the image is running: the string the
/// `rust_uefi_module` detector family and the range suites grep for.
pub const BOOT_MARKER: &[u8] = b"BARZAKH-RUSTKIT-BOOTED";

/// Self-test arena: 4 KiB, canary-managed like an SMRAM window.
static mut ARENA: [u8; 4096] = [0; 4096];

/// `r_efi` GUID for EFI_SIMPLE_NETWORK_PROTOCOL: {A19832B9-AC25-11D3-9A2D-0090273FC14D}.
const SIMPLE_NETWORK_GUID: r_efi::base::Guid = r_efi::base::Guid::from_fields(
    0xa198_32b9,
    0xac25,
    0x11d3,
    0x9a,
    0x2d,
    &[0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d],
);

/// EFI error code for a kill-switch abort (EFI_ABORTED = 21 | error bit).
const EFI_ABORTED: usize = 21 | (0x80 << (usize::BITS - 8));

/// Read the current Unix time through UEFI runtime services, if available.
fn now_unix(st: &r_efi::system::SystemTable) -> Option<u64> {
    let rt = st.runtime_services;
    if rt.is_null() {
        return None;
    }
    let get_time = unsafe { (*rt).get_time };
    let mut time: r_efi::system::Time = unsafe { core::mem::zeroed() };
    let status = unsafe { get_time(&mut time, core::ptr::null_mut()) };
    if status != r_efi::base::Status::SUCCESS {
        return None;
    }
    // Convert EFI_TIME to Unix seconds. Leap-day precision is irrelevant
    // for a kill-switch date comparison; a day-level approximation is
    // enough because EXPIRY_UNIX is a hard cut, never a tight window.
    let year = time.year.max(1970) as u64;
    let days = (year - 1970) * 365
        + ((year - 1969) / 4) // leap days
        + day_of_year(time.month, time.day);
    Some(
        (days * 86_400)
            + (time.hour as u64) * 3_600
            + (time.minute as u64) * 60
            + time.second as u64,
    )
}

fn day_of_year(month: u8, day: u8) -> u64 {
    const CUM: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let m = (month.clamp(1, 12) - 1) as usize;
    // 0-based days elapsed: Jan 1 → 0, Dec 31 → 364 (non-leap).
    CUM[m] + day.saturating_sub(1) as u64
}

/// Probe whether any network stack is present (air-gap check).
fn network_present(st: &r_efi::system::SystemTable) -> bool {
    let bs = st.boot_services;
    if bs.is_null() {
        return false;
    }
    let locate = unsafe { (*bs).locate_protocol };
    let mut interface: *mut core::ffi::c_void = core::ptr::null_mut();
    let status = unsafe {
        locate(
            &SIMPLE_NETWORK_GUID as *const r_efi::base::Guid as *mut r_efi::base::Guid,
            core::ptr::null_mut(),
            &mut interface,
        )
    };
    status == r_efi::base::Status::SUCCESS
}

/// The CommBuffer confused-deputy self-test. Returns `true` when the
/// canary caught the simulated overrun and the log verified — i.e. the
/// defensive prototype works.
fn commbuffer_self_test(arena: &mut [u8]) -> bool {
    // 1. Hardened validation rejects the attacker buffer (declared
    //    0x1000-byte message in a 4-byte payload).
    let mut attacker_buffer = [0u8; commbuffer::COMM_HEADER_LEN + 4];
    let n = commbuffer::build_into(
        commbuffer::HANDLER_GUID,
        0x1000,
        &[1, 2, 3, 4],
        &mut attacker_buffer,
    )
    .unwrap_or(0);
    let rejected = matches!(
        commbuffer::validate_hardened(&attacker_buffer[..n]),
        Verdict::Invalid(Reason::LengthOverrun)
    );

    // 2. The TOCTOU oracle: a buffer that validates to one length on the
    //    first fetch and a different (still-valid) length on the second
    //    fetch is detected as a double-fetch attack.
    let mut before = [0u8; commbuffer::COMM_HEADER_LEN + 4];
    let mut after = [0u8; commbuffer::COMM_HEADER_LEN + 4];
    commbuffer::build_into(commbuffer::HANDLER_GUID, 4, &[1, 2, 3, 4], &mut before);
    commbuffer::build_into(commbuffer::HANDLER_GUID, 2, &[1, 2, 3, 4], &mut after);
    let toctou = matches!(
        commbuffer::validate_vulnerable(&before, &after),
        Verdict::Invalid(Reason::Toctou)
    );

    // 3. Canary-guarded copy: a handler that (mistakenly) trusts the
    //    declared length overruns into the guard band; the trap-page
    //    allocator catches it and the handler survives.
    // Capture the base pointer before the allocator borrows the arena —
    // the attack write must bypass every safe API anyway.
    let ptr = arena.as_mut_ptr();
    let mut alloc = TrapPageAllocator::new(arena);
    let Some((start, len)) = alloc.alloc(64) else {
        return false;
    };
    let declared: usize = 0x1000.min(len + 2 * GUARD_SIZE); // bounded overrun
    // Simulated out-of-bounds copy.
    for i in 0..declared {
        unsafe { *ptr.add(start + i) = 0xB5 };
    }
    let fault = match alloc.integrity() {
        Err(f) => f,
        Ok(()) => return false,
    };
    let mut log = ProtectedLog::new();
    alloc.log_fault(&fault, &mut log);
    let logged = log.count() == 1 && log.verify();

    rejected && toctou && logged
}

/// RustKit module body: returns an EFI status code (`usize`).
///
/// Called from the `efi_main` export in the `rustkit-dxe` bin. The entry
/// point is single-threaded; the static arena is accessed exclusively.
///
/// # Safety
///
/// `st` must be a valid UEFI System Table pointer (guaranteed by the
/// firmware entry-point contract) or null.
pub unsafe fn run(_image: r_efi::base::Handle, st: *mut r_efi::system::SystemTable) -> usize {
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        serial::writeln(crate::RUSTKIT_BANNER);
        serial::writeln(BOOT_MARKER);
        serial::write(b"mode=simulation=");
        serial::putb(b'0' + mode::SIMULATION_MODE as u8);
        serial::writeln(b"");
    }

    // Kill-switches. A null system table (defensive) skips the
    // firmware-service probes but still runs the self-test.
    let (now, net) = if st.is_null() {
        (None, false)
    } else {
        // SAFETY: checked non-null above; the entry-point contract
        // guarantees validity for the lifetime of the call.
        let table = unsafe { &*st };
        (now_unix(table), network_present(table))
    };
    match mode::boot_gate(now, net) {
        Gate::Blocked(reason) => {
            #[cfg(all(target_arch = "x86_64", not(test)))]
            {
                serial::writeln(b"KILLSWITCH: module refused to initialize");
                let _ = reason;
            }
            let _ = reason;
            return EFI_ABORTED;
        }
        Gate::Allowed => {}
    }

    // Self-test (single-threaded entry point: exclusive arena access).
    let arena: &mut [u8] = unsafe { &mut *core::ptr::addr_of_mut!(ARENA) };
    let ok = commbuffer_self_test(arena);
    #[cfg(all(target_arch = "x86_64", not(test)))]
    {
        if ok {
            serial::writeln(b"CANARY-SELFTEST-PASS");
            serial::writeln(b"BARZAKH-RUSTKIT-SMI-HANDLER-SURVIVED");
        } else {
            serial::writeln(b"CANARY-SELFTEST-FAIL");
        }
    }
    if !ok {
        return EFI_ABORTED;
    }

    #[cfg(all(target_arch = "x86_64", not(test)))]
    serial::writeln(b"BARZAKH-RUSTKIT-EXIT");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_test_catches_overrun_on_host() {
        let mut arena = [0u8; 4096];
        assert!(commbuffer_self_test(&mut arena));
    }

    #[test]
    fn day_of_year_sane() {
        assert_eq!(day_of_year(1, 1), 0);
        assert_eq!(day_of_year(12, 31), 364);
    }

    #[test]
    fn aborted_status_matches_efi_encoding() {
        // EFI_ABORTED = 21 with the error bit set for 64-bit usize.
        assert_eq!(EFI_ABORTED, 0x8000_0000_0000_0015);
    }
}
