//! Kill-switch discipline for RustKitPkg — the Rust mirror of BootkitPkg's
//! `Include/BarzakhMode.h`.
//!
//! * **Simulation-first** (default, and the only mode CI builds): all
//!   hardware-modifying operations are logged and skipped. Nothing outside
//!   the module's own memory is ever changed.
//! * **Functional** (`--features functional`): real hardware paths execute.
//!   Lab-only. Refuses to compile without `barzakh_research` — the
//!   research-use gate.
//! * **Time-bomb**: functional builds refuse to initialize after
//!   [`EXPIRY_UNIX`]. Simulation builds only warn.
//! * **Air-gap**: initialization aborts when a network stack is present,
//!   so research modules never run on networked machines by accident.

/// Compile-time research-use gate: `functional` without `barzakh_research`
/// must not build. (The Cargo features wire `functional = ["barzakh_research"]`,
/// so reaching an inconsistent state requires hand-editing the manifest —
/// this check catches that.)
#[cfg(all(feature = "functional", not(feature = "barzakh_research")))]
compile_error!("feature `functional` requires `barzakh_research` (research-use gate)");

/// `true` when this is a simulation build (default).
pub const SIMULATION_MODE: bool = !cfg!(feature = "functional");

/// Time-bomb: functional builds refuse to initialize past this instant
/// (2027-01-01T00:00:00Z). Research binaries must not outlive their review.
pub const EXPIRY_UNIX: u64 = 1_798_761_600;

/// Verdict of the boot-time kill-switch checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    /// Initialization may proceed.
    Allowed,
    /// Initialization must abort; carries the reason.
    Blocked(&'static str),
}

/// Time-bomb check. `now_unix` is the current time from UEFI runtime
/// services (`GetTime`); `None` when the clock is unavailable (treated as
/// not expired — the check only *blocks*, never fabricates a date).
pub fn time_bomb(now_unix: Option<u64>) -> Gate {
    match (now_unix, SIMULATION_MODE) {
        (Some(now), false) if now >= EXPIRY_UNIX => Gate::Blocked("time-bomb expired"),
        (Some(_), false) => Gate::Allowed,
        // Simulation builds never hard-block on the clock; they only warn.
        _ => Gate::Allowed,
    }
}

/// Air-gap check. `network_present` is whether a network stack was found
/// (SimpleNetwork / iPXE / HTTP Boot protocols reachable). Any network on
/// a machine running research firmware is a hard abort in every mode.
pub fn air_gap(network_present: bool) -> Gate {
    if network_present {
        Gate::Blocked("air-gap violation: network stack present")
    } else {
        Gate::Allowed
    }
}

/// Combine all gates for the boot decision.
pub fn boot_gate(now_unix: Option<u64>, network_present: bool) -> Gate {
    match (time_bomb(now_unix), air_gap(network_present)) {
        (Gate::Allowed, Gate::Allowed) => Gate::Allowed,
        (Gate::Blocked(r), _) | (_, Gate::Blocked(r)) => Gate::Blocked(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulation_mode_is_default() {
        // CI builds without features: simulation must be the default.
        // (A functional test build would assert !SIMULATION_MODE.)
        assert_eq!(SIMULATION_MODE, !cfg!(feature = "functional"));
    }

    #[test]
    fn time_bomb_blocks_functional_after_expiry() {
        if SIMULATION_MODE {
            // Simulation builds only warn — never hard-block on the clock.
            assert_eq!(time_bomb(Some(EXPIRY_UNIX + 1)), Gate::Allowed);
        } else {
            assert!(matches!(time_bomb(Some(EXPIRY_UNIX + 1)), Gate::Blocked(_)));
        }
    }

    #[test]
    fn time_bomb_allows_before_expiry() {
        assert_eq!(time_bomb(Some(0)), Gate::Allowed);
        assert_eq!(time_bomb(None), Gate::Allowed);
    }

    #[test]
    fn air_gap_blocks_network() {
        assert!(matches!(air_gap(true), Gate::Blocked(_)));
        assert_eq!(air_gap(false), Gate::Allowed);
    }

    #[test]
    fn boot_gate_combines() {
        assert_eq!(boot_gate(None, false), Gate::Allowed);
        assert!(matches!(boot_gate(None, true), Gate::Blocked(_)));
    }
}
