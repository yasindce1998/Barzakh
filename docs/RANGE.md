# Cyber Range — Ring -2 Attack → Detect → Assert

The Barzakh cyber range reproduces the full firmware attack loop against
**real** virtual-machine firmware, headless, in one command:

```
barzakh-scanner range up --suite ring-2
```

It boots a QEMU q35 machine (SMM emulation on, swtpm-backed TPM 2.0, OVMF
firmware), deploys adversary payloads through a spec-conformant FAT ESP at
the removable boot path — the same vector LoJax and BlackLotus used
(`\EFI\BOOT\BOOTX64.EFI` on a USB storage device) — lets the firmware's own
boot manager `LoadImage()`/`StartImage()` the dropper, captures guest RAM
through the QEMU monitor, scans every artifact with the Barzakh scanner,
and asserts the expected detections. When a case fails the command exits
non-zero and prints exactly which assertion was violated.

Everything is **simulation-only**: payloads are synthetic byte patterns,
never real exploit code, and every payload family ships a kill-switched
(dormant) variant used as the falsifiable negative control.

## Suites

| Suite | Manifest | Purpose |
|---|---|---|
| `ring-2` | `range/ring-2.toml` | Armed implants must be detected on the deployed artifacts (and, for payload-attributable detectors, in the captured guest RAM). Includes a clean golden-boot control. |
| `intentional-miss` | `range/intentional-miss.toml` | Kill-switched implant variants deployed through the exact same pipeline **must NOT** be detected. Proves the assertion path can fail. |

Current cases include `boot_services_hook`, `smm_timing_anomaly`,
`pxe_icmp_overflow` (CVE-2026-97631) and a `none` (clean) control, each in
armed and dormant variants.

## How a case runs

1. **Generate** — the payload bytes are generated with
   `barzakh-adversary` (deterministic; `dormant = true` produces the
   kill-switched variant).
2. **Deploy** — the payload is wrapped as a minimal, valid x64 UEFI PE
   application (`deploy/efi_app.rs`: entry stub `xor eax,eax; ret`, payload
   embedded in an `.fsh` section) and placed at
   `\EFI\BOOT\BOOTX64.EFI` on a FAT16 superfloppy ESP. The ESP is attached
   as **removable USB storage** (`qemu-xhci` + `usb-storage,removable=on`),
   so OVMF expands the short-form boot option and actually loads and runs
   the dropper — a valid PE the firmware will happily start, carrying the
   implant bytes into RAM.
3. **Boot** — QEMU (q35, `smm=on`, `-display none`, serial-to-file, HMP
   monitor on a unix socket, pflash OVMF CODE/VARS, `tpm-tis` over swtpm)
   runs until a boot-completion marker appears on serial: the dropper
   starting (`BdsDxe: starting Boot…`), the boot-manager menu, or the UEFI
   shell.
4. **Capture** — guest RAM is dumped with `pmemsave` via the monitor, then
   the VM is powered off.
5. **Detect** — every artifact (ESP image, dropper, implant blob, memory
   dump) is scanned with the full Barzakh detector suite.
6. **Assert** — see below.

## Assertion semantics

- `expect_findings` — detector names that MUST fire on the **deployment
  artifacts** (ESP image, dropper, implant blob). Deterministic evidence
  directly attributable to the implant.
- `expect_absent` — detector names that must NOT fire on the deployment
  artifacts. The intentional-miss suite uses these on dormant variants.
- `expect_in_memory` — detector names that must also fire in the
  **captured guest RAM**: proof the implant was actually deployed and
  resident in the live guest. Only used where a finding is unambiguously
  attributable to the implant.
- A `payload = "none"` case additionally asserts the deployment artifacts
  stay verdict-clean.

Captured guest memory is *real* firmware state: genuine OVMF structures
(real RUNT tables, SMM save-state shapes) legitimately trip medium-severity
heuristics. Memory findings are therefore recorded as live-range evidence
and only ever **positively** asserted — never used for absence claims.

## Tooling

QEMU, swtpm and OVMF are discovered automatically:

1. `BARZAKH_QEMU` / `BARZAKH_SWTPM` / `BARZAKH_OVMF_CODE` / `BARZAKH_OVMF_VARS`
   environment variables,
2. `PATH`,
3. `~/barzakh-tools` prefix (created by `scripts/install-range-tools.sh`,
   which downloads qemu-system-x86_64, swtpm and OVMF into a user prefix —
   `LD_LIBRARY_PATH` is injected automatically),
4. system OVMF locations (`/usr/share/edk2/x64`, `/usr/share/OVMF`, …).

No ROM binaries are required: the VM runs with `-vga none`.

## Commands

```
# list available suites
barzakh-scanner range list

# validate manifests/payloads and print the planned QEMU invocation
# (works without QEMU installed — this is what CI falls back to)
barzakh-scanner range up --suite ring-2 --dry-run

# full live run; artifacts land in build/range/case-*/
barzakh-scanner range up --suite ring-2 --keep

# JSON report
barzakh-scanner range up --suite ring-2 --json

# skip the (slow) guest-memory scan
barzakh-scanner range up --suite ring-2 --skip-memory-scan
```

Per-case artifacts (kept with `--keep`): `serial.log` (firmware debug +
console), `debug.log` (OVMF debugcon), `qemu.err`, `esp.img` (the deployed
FAT ESP), `dropper.efi` (the PE-wrapped implant), `implant.bin` (raw
payload bytes), `mem.bin` (guest RAM capture) and the swtpm state. A
captured boot serial log is kept as evidence at
`docs/evidence/range-pxe-icmp-overflow-boot.log` — note the
`BdsDxe: starting Boot0002 "UEFI QEMU QEMU USB HARDDRIVE"` lines proving
the firmware actually loaded and started the deployed dropper.

## Writing a new case

Add a block to a suite manifest:

```toml
[[cases]]
name = "my-attack"
payload = "boot_services_hook"   # any barzakh-adversary payload name, or "none"
dormant = true                   # optional: kill-switched variant
expect_findings = ["hook"]
expect_in_memory = ["hook"]      # optional: must also fire in captured RAM
expect_absent = []               # optional: must NOT fire
```

Range-level knobs: `memory_mb`, `timeout_secs`, `smm`, `tpm`.

## Safety stance

The range inherits Barzakh's anti-CHIPSEC stance: no kernel modules, no
`/dev/mem`, no raw-memory IOCTLs — everything runs as an unprivileged
user-space QEMU workload. Payloads are synthetic detector-fodder, never
functional exploit code; malicious samples are never auto-fetched.
