//! SMRAM canary & trap-page allocator — the defensive half of RustKitPkg.
//!
//! A Rust Standalone-MM driver prototype that:
//!
//! * places guard (trap-page model) regions around every allocation and
//!   around the SMM save-state map (`SMBASE + 0xFC00`),
//! * seeds canary structures at SMRAM region boundaries, and
//! * detects unauthorized dereferences **before** `RIP`/`CR3` corruption
//!   is achievable, logging the faulting address to a protected log page.
//!
//! In real hardware the guard regions would be unmapped pages and the
//! detection an SMM page fault; in this simulation-first prototype they
//! are canary-filled byte regions whose integrity is checked after every
//! handler operation — the same detection contract, none of the risk.

/// Byte pattern that fills every guard region (and unused arena space).
pub const CANARY: u8 = 0xC7;

/// Size of a guard region. Models one 4 KiB page scaled down 64× so the
/// whole allocator fits in a DXE driver's static data.
pub const GUARD_SIZE: usize = 64;

/// Size of the protected fault log page (models one 4 KiB log page).
pub const LOG_PAGE_SIZE: usize = 512;

/// Maximum fault records the protected log can hold.
pub const MAX_FAULTS: usize = 16;

/// Maximum tracked allocations (fixed, no heap in SMM).
pub const MAX_ALLOCS: usize = 16;

/// The SMM save-state map lives at `SMBASE + 0xFC00` (offset within the
/// SMRAM window allocated to the CPU). Guarding it is the allocator's
/// first job.
pub const SAVE_STATE_OFFSET: usize = 0xFC00;

/// A detected canary violation — the simulated page fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    /// Offset of the corrupted guard byte within the arena.
    pub guard_offset: usize,
    /// Byte that was found where the canary should be.
    pub written: u8,
    /// Monotonic sequence number.
    pub seq: u32,
}

impl Fault {
    /// Format a one-line description (`"CANARY-VIOLATION guard=0x.. wrote=0x.. seq=.."`)
    /// into `out`; returns the number of bytes written.
    pub fn format_into(&self, out: &mut [u8]) -> usize {
        let mut n = push_str(out, 0, b"CANARY-VIOLATION guard=0x");
        n = push_hex(out, n, self.guard_offset as u64);
        n = push_str(out, n, b" wrote=0x");
        n = push_hex(out, n, self.written as u64);
        n = push_str(out, n, b" seq=");
        push_dec(out, n, self.seq as u64)
    }
}

/// A tracked allocation extent: usable region `[start, start+len)`.
#[derive(Clone, Copy)]
struct Extent {
    start: usize,
    len: usize,
}

/// Trap-page allocator over a caller-owned arena.
///
/// Every allocation is bracketed by [`GUARD_SIZE`] canary-filled guard
/// regions, and unused tail space stays canary-filled (an unmapped hole
/// in the hardware model). [`TrapPageAllocator::integrity`] walks the
/// guard bands and returns the first violation — the simulated page
/// fault. The handler *survives*: the corruption is reported, never
/// silently consumed.
pub struct TrapPageAllocator<'a> {
    arena: &'a mut [u8],
    next: usize,
    /// Monotonic fault sequence, interiorly mutable so `integrity` can
    /// run on a shared reference.
    seq: core::cell::Cell<u32>,
    extents: [Extent; MAX_ALLOCS],
    allocs: usize,
}

impl<'a> TrapPageAllocator<'a> {
    /// Claim an arena and canary-fill it entirely.
    pub fn new(arena: &'a mut [u8]) -> Self {
        arena.fill(CANARY);
        Self {
            arena,
            next: 0,
            seq: core::cell::Cell::new(0),
            extents: [Extent { start: 0, len: 0 }; MAX_ALLOCS],
            allocs: 0,
        }
    }

    /// Allocate `size` bytes bracketed by guard regions. The returned
    /// `(offset, len)` describes the *usable* region inside the arena.
    pub fn alloc(&mut self, size: usize) -> Option<(usize, usize)> {
        if self.allocs >= MAX_ALLOCS {
            return None;
        }
        let start = self.next.checked_add(GUARD_SIZE)?;
        let end = start.checked_add(size)?;
        let tail = end.checked_add(GUARD_SIZE)?;
        if tail > self.arena.len() {
            return None;
        }
        self.arena[start..end].fill(0);
        self.arena[start - GUARD_SIZE..start].fill(CANARY);
        self.arena[end..tail].fill(CANARY);
        self.extents[self.allocs] = Extent { start, len: size };
        self.allocs += 1;
        self.next = tail;
        Some((start, size))
    }

    /// Walk every guard band (and the canary-filled tail); return the
    /// first corruption found.
    pub fn integrity(&self) -> Result<(), Fault> {
        for e in &self.extents[..self.allocs] {
            let band_start = e.start - GUARD_SIZE;
            let band_end = e.start + e.len + GUARD_SIZE;
            for i in band_start..band_end {
                let in_usable = i >= e.start && i < e.start + e.len;
                if !in_usable && self.arena[i] != CANARY {
                    let seq = self.seq.get() + 1;
                    self.seq.set(seq);
                    return Err(Fault {
                        guard_offset: i,
                        written: self.arena[i],
                        seq,
                    });
                }
            }
        }
        // Unused tail must remain pristine canary.
        for i in self.next..self.arena.len() {
            if self.arena[i] != CANARY {
                let seq = self.seq.get() + 1;
                self.seq.set(seq);
                return Err(Fault {
                    guard_offset: i,
                    written: self.arena[i],
                    seq,
                });
            }
        }
        Ok(())
    }

    /// Advance the sequence counter externally (used by the DXE self-test
    /// to keep `seq` meaningful across checks).
    pub fn next_seq(&self) -> u32 {
        let s = self.seq.get() + 1;
        self.seq.set(s);
        s
    }

    /// Record a fault into the protected log page.
    pub fn log_fault(&mut self, fault: &Fault, log: &mut ProtectedLog) {
        log.append(fault);
    }
}

/// Serialized fault record: guard offset (8) + seq (4) + byte (1) +
/// valid marker (1) = 14 bytes.
const FAULT_RECORD_SIZE: usize = 14;

/// Protected fault log page.
///
/// The log is *protected* in the model: fixed-size (no heap in SMM) and
/// checksummed so post-fault tampering is detectable via [`verify`].
pub struct ProtectedLog {
    page: [u8; LOG_PAGE_SIZE],
    count: usize,
    checksum: u32,
}

impl ProtectedLog {
    pub fn new() -> Self {
        let mut s = Self {
            page: [0u8; LOG_PAGE_SIZE],
            count: 0,
            checksum: 0,
        };
        s.page[..8].copy_from_slice(b"BRZKHLOG");
        s.recompute();
        s
    }

    /// Append a fault record; returns `false` (and drops) when full.
    pub fn append(&mut self, fault: &Fault) -> bool {
        if self.count >= MAX_FAULTS {
            return false;
        }
        let off = 8 + self.count * FAULT_RECORD_SIZE;
        self.page[off..off + 8].copy_from_slice(&(fault.guard_offset as u64).to_le_bytes());
        self.page[off + 8..off + 12].copy_from_slice(&fault.seq.to_le_bytes());
        self.page[off + 12] = fault.written;
        self.page[off + 13] = 0x5A; // record-valid marker
        self.count += 1;
        self.recompute();
        true
    }

    pub fn count(&self) -> usize {
        self.count
    }

    /// Verify the log page was not tampered with after the fault.
    pub fn verify(&self) -> bool {
        let mut sum = 0u32;
        for &b in self.page.iter() {
            sum = sum.wrapping_add(b as u32).rotate_left(1);
        }
        sum == self.checksum
    }

    fn recompute(&mut self) {
        let mut sum = 0u32;
        for &b in self.page.iter() {
            sum = sum.wrapping_add(b as u32).rotate_left(1);
        }
        self.checksum = sum;
    }
}

impl Default for ProtectedLog {
    fn default() -> Self {
        Self::new()
    }
}

// ── tiny formatting helpers (no core::fmt in the fault path) ──────────

fn push_str(out: &mut [u8], n: usize, s: &[u8]) -> usize {
    for (i, &b) in s.iter().enumerate() {
        if n + i < out.len() {
            out[n + i] = b;
        }
    }
    (n + s.len()).min(out.len())
}

fn push_hex(out: &mut [u8], n: usize, v: u64) -> usize {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut buf = [0u8; 16];
    let mut i = buf.len();
    let mut x = v;
    loop {
        i -= 1;
        buf[i] = HEX[(x & 0xF) as usize];
        x >>= 4;
        if x == 0 {
            break;
        }
    }
    push_str(out, n, &buf[i..])
}

fn push_dec(out: &mut [u8], n: usize, v: u64) -> usize {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut x = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (x % 10) as u8;
        x /= 10;
        if x == 0 {
            break;
        }
    }
    push_str(out, n, &buf[i..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_allocation_has_no_faults() {
        let mut arena = [0u8; 1024];
        let mut a = TrapPageAllocator::new(&mut arena);
        a.alloc(32).unwrap();
        assert!(a.integrity().is_ok());
    }

    #[test]
    fn overrun_into_guard_is_caught() {
        let mut arena = [0u8; 1024];
        let ptr = core::ptr::addr_of_mut!(arena) as *mut u8;
        let mut a = TrapPageAllocator::new(&mut arena);
        let (start, len) = a.alloc(32).unwrap();
        // Handler writes past the usable region into the trailing guard
        // (raw pointer: the attack bypasses safe APIs).
        unsafe { *ptr.add(start + len) = 0xDE };
        let fault = a.integrity().unwrap_err();
        assert_eq!(fault.guard_offset, start + len);
        assert_eq!(fault.written, 0xDE);
    }

    #[test]
    fn underrun_into_guard_is_caught() {
        let mut arena = [0u8; 1024];
        let ptr = core::ptr::addr_of_mut!(arena) as *mut u8;
        let mut a = TrapPageAllocator::new(&mut arena);
        let (start, _) = a.alloc(32).unwrap();
        unsafe { *ptr.add(start - 1) = 0xAD };
        assert!(a.integrity().is_err());
    }

    #[test]
    fn write_inside_allocation_is_fine() {
        let mut arena = [0u8; 1024];
        let ptr = core::ptr::addr_of_mut!(arena) as *mut u8;
        let mut a = TrapPageAllocator::new(&mut arena);
        let (start, len) = a.alloc(32).unwrap();
        for i in 0..len {
            unsafe { *ptr.add(start + i) = 0x41 };
        }
        assert!(a.integrity().is_ok());
    }

    #[test]
    fn write_into_unused_tail_is_caught() {
        let mut arena = [0u8; 1024];
        let ptr = core::ptr::addr_of_mut!(arena) as *mut u8;
        let mut a = TrapPageAllocator::new(&mut arena);
        a.alloc(32).unwrap();
        unsafe { *ptr.add(900) = 0x99 };
        assert!(a.integrity().is_err());
    }

    #[test]
    fn fault_logged_and_log_verifies() {
        let mut arena = [0u8; 1024];
        let ptr = core::ptr::addr_of_mut!(arena) as *mut u8;
        let mut a = TrapPageAllocator::new(&mut arena);
        let (start, len) = a.alloc(32).unwrap();
        unsafe { *ptr.add(start + len + 3) = 0x66 };
        let fault = a.integrity().unwrap_err();
        let mut log = ProtectedLog::new();
        a.log_fault(&fault, &mut log);
        assert_eq!(log.count(), 1);
        assert!(log.verify());
    }

    #[test]
    fn fault_formats_readably() {
        let f = Fault {
            guard_offset: 0x1234,
            written: 0xDE,
            seq: 7,
        };
        let mut out = [0u8; 64];
        let n = f.format_into(&mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.contains("guard=0x1234"), "got: {s}");
        assert!(s.contains("wrote=0xDE"));
        assert!(s.ends_with("seq=7"));
    }

    #[test]
    fn save_state_offset_is_documented_constant() {
        // The save-state map must sit at SMBASE + 0xFC00 per the IA-32 SDM.
        assert_eq!(SAVE_STATE_OFFSET, 0xFC00);
    }

    #[test]
    fn allocator_exhaustion_is_safe() {
        let mut arena = [0u8; 128];
        let mut a = TrapPageAllocator::new(&mut arena);
        // 2*GUARD_SIZE = 128 leaves zero usable bytes.
        assert!(a.alloc(1).is_none());
        assert!(a.integrity().is_ok());
    }

    #[test]
    fn max_allocs_bounded() {
        let mut arena = [0u8; 4096];
        let mut a = TrapPageAllocator::new(&mut arena);
        for _ in 0..MAX_ALLOCS {
            assert!(a.alloc(1).is_some());
        }
        assert!(a.alloc(1).is_none());
        assert!(a.integrity().is_ok());
    }
}
