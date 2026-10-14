# RustKitPkg — Pure-Rust `no_std` UEFI Research Modules

> Barzakh Phase 5 / Pillar 3. The firmware industry is migrating from C/EDK II
> toward pure-Rust cores (Patina and allied efforts). The Ring -2 vulnerability
> class shifts from buffer overflows to **FFI and confused-deputy boundaries**
> between legacy C SMM drivers and Rust components. RustKitPkg owns the
> offensive *and* defensive research tooling for that boundary.

## Layout

| Module | Side | What it does |
|---|---|---|
| `src/mode.rs` | discipline | Kill-switches: simulation-first, research gate, time-bomb, air-gap |
| `src/commbuffer.rs` | offense | C↔Rust CommBuffer confused-deputy model: *vulnerable* double-fetch validation (adversary/fuzzer model) + *hardened* single-copy validation |
| `src/canary.rs` | defense | SMRAM canary & trap-page allocator: guard regions around every allocation and the SMM save-state map (`SMBASE + 0xFC00`), protected fault-log page |
| `src/serial.rs` | infra | 16550 UART output (COM1) so range boots produce visible markers |
| `src/dxe.rs` | firmware | DXE module body: boot gate, CommBuffer confused-deputy self-test |
| `src/main.rs` | firmware | Freestanding `efi_main` shell (`--features firmware`) |

## Build & test

```bash
# Host unit tests (24 tests; logic runs with std)
cargo test

# Firmware image for the range (x86_64-unknown-uefi must be installed:
#   rustup target add x86_64-unknown-uefi)
cargo build --release --target x86_64-unknown-uefi --features firmware
# → target/x86_64-unknown-uefi/release/rustkit-dxe.efi  (~3.5 KB PE32+)
```

## Booting in the range (proven)

Build a bootable FAT16 ESP with the image and boot it under OVMF (q35, SMM,
swtpm TPM 2.0):

```bash
cd src/barzakh-scanner-rs
cargo run -p barzakh-cli --bin barzakh-adversary -- \
    esp build --payload <path>/rustkit-dxe.efi --output esp.img --size 16 --bootable

swtpm socket --tpmstate dir=tpm --ctrl type=unixio,path=tpm/sock --tpm2 --daemon
qemu-system-x86_64 -machine q35,smm=on -m 512 -nodefaults -display none \
    -vga none -net none \
    -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.4m.fd \
    -drive if=pflash,format=raw,file=OVMF_VARS.fd \
    -drive format=raw,file=esp.img \
    -chardev socket,id=chrtpm,path=tpm/sock -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device tpm-tis,tpmdev=tpm0 -serial file:serial.log
```

The serial log then shows (see `docs/evidence/rustkit-ovmf-boot.log` for a
captured run):

```
BARZAKH-RUSTKIT-BOOTED
mode=simulation=1
CANARY-SELFTEST-PASS
BARZAKH-RUSTKIT-SMI-HANDLER-SURVIVED
BARZAKH-RUSTKIT-EXIT
```

i.e. the Phase 5 acceptance criteria: the Rust DXE module boots inside range
OVMF, the canary/trap-page allocator catches a simulated CommBuffer overrun
(fault logged to the protected page), and the SMI handler survives.

## Kill-switch discipline (mirrors BootkitPkg `BarzakhMode.h`)

* **SIMULATION (default, the only mode CI builds)** — nothing outside the
  module's own memory is ever changed. `mode::SIMULATION_MODE == true`.
* **FUNCTIONAL (`--features functional`)** — real hardware paths; lab-only.
  Refuses to compile without `barzakh_research` (compile-time gate), and
  requires it transitively through the feature graph.
* **Time-bomb** — functional builds refuse to initialize after
  `mode::EXPIRY_UNIX` (2027-01-01). Simulation builds only warn.
* **Air-gap** — initialization aborts whenever a network stack
  (SimpleNetwork) is present, in every mode. Range boots use `-net none`.

## Detection & adversary integration

* `rust_uefi_module` detector (barzakh-core) recognizes Rust-compiled UEFI
  binaries (`/rustc/` compiler path string, RustKit marker GUID) and the
  **CommBuffer confused-deputy (TOCTOU) pattern**: a handler-GUID-routed
  `EFI_SMM_COMMUNICATE_HEADER` whose declared `MessageLength` exceeds the
  bytes present — the double-fetch primitive codified as a detection rule
  after the boundary fuzzer surfaced it (`barzakh-core/src/fuzz.rs`,
  `Protocol::CommBuffer`).
* `rustkit_implant` payload — unsigned Rust-UEFI implant model.
* `commbuffer_toctou` payload — the double-fetch buffer model.
* `scripts/install-range-tools.sh` installs QEMU + swtpm + OVMF into a user
  prefix without root.
