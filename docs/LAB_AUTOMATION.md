# Barzakh: Hardware Lab Automation

> **Last Updated:** 2026-10-13 | **Applies to:** `scripts/hil-runner.sh`, `scripts/jtag-monitor.sh`

---

## ⚠️ Critical Warnings

**READ [LAB_TESTING.md](LAB_TESTING.md) BEFORE USING ANYTHING ON THIS PAGE.**

| Risk | Description |
|------|-------------|
| **Hardware Brick** | The `flash` and `recover` phases erase and rewrite the SPI flash. A failed write can permanently brick the board. |
| **Warranty Void** | Attaching programmers or debug probes voids manufacturer warranty. |
| **Data Loss** | A bad flash can destroy NVRAM (UEFI variables, BitLocker keys, Secure Boot keys). |
| **ME/PSP Damage** | Corrupting the Management Engine or PSP region can cause irreversible boot delays or total board failure. |

**These scripts assume a dedicated, sacrificial test machine in an air-gapped lab — exactly as LAB_TESTING.md prescribes. Never point them at production hardware.**

---

## 🎯 Overview

`scripts/hil-runner.sh` automates the real-silicon (hardware-in-the-loop) test path as five discrete phases, each runnable independently. `scripts/jtag-monitor.sh` captures physical debug-interface (JTAG/SWD) traces with OpenOCD during a test run. Both feed their artifacts back into the scanner and the knowledge base.

```
┌────────┐  phase read   ┌────────┐  phase inject  ┌─────────┐  phase flash  ┌──────────┐
│  SPI   │──────────────▶│ backup │───────────────▶│modified │──────────────▶│  target  │
│ flash  │  flashrom -r  │ .bin   │ barzakh-adversary│ image │  flashrom -w  │  board   │
└────────┘  (read twice, └────────┘ inject-single  └─────────┘  (risky!)     └────┬─────┘
            checksum)                                                   │
                                                                    phase verify
                                                                            │
                 ┌────────────────────────┐  phase recover   ┌────────────▼─────────┐
                 │  Knowledge base +      │◀─────────────────│ barzakh-scanner scan │
                 │  detector tuning       │  restore backup  │ + report (JSON/HTML) │
                 └────────────────────────┘                  └──────────────────────┘
```

Back to [README](../README.md) · Full safety prerequisites: [LAB_TESTING.md](LAB_TESTING.md).

---

## 🔧 hil-runner.sh — Five Phases

```bash
# Phase 1: read — full backup, read twice with checksum comparison
SIMULATION=1 ./hil-runner.sh --phase read --backup fw-backup.bin --programmer ch341a_spi

# Phase 2: inject — build a modified image (file only, no hardware touched)
SIMULATION=1 ./hil-runner.sh --phase inject --image fw-backup.bin --payload acpi_backdoor

# Phase 3: flash — write the modified image (DESTRUCTIVE)
SIMULATION=0 ./hil-runner.sh --phase flash --image test/hil/injected.bin \
    --backup fw-backup.bin --programmer ch341a_spi --i-understand-the-risks

# Phase 4: verify — scan and report
./hil-runner.sh --phase verify --image test/hil/injected.bin

# Phase 5: recover — restore the backup (DESTRUCTIVE)
SIMULATION=0 ./hil-runner.sh --phase recover --backup fw-backup.bin \
    --programmer ch341a_spi --i-understand-the-risks
```

| Phase | Risk | What it does |
|-------|------|--------------|
| `read` | None | `flashrom -r` twice, `cmp` the reads — a trusted backup per LAB_TESTING.md Step 1 |
| `inject` | None | `barzakh-adversary inject-single --input ... --output ... --payload ...` — file-only |
| `flash` | **Medium-High** | `flashrom -w` + `-v` the injected image |
| `verify` | None | `barzakh-scanner scan` + HTML/JSON reports |
| `recover` | **Medium** | `flashrom -w` + `-v` the backup image |

### Options

| Option | Purpose |
|--------|---------|
| `--phase` | One of `read`, `inject`, `flash`, `verify`, `recover` (required) |
| `--image` | Firmware image (inject input; flash/verify target) |
| `--backup` | Backup path (read output; flash/recover recovery reference) |
| `--programmer` | flashrom `-p` argument (default `internal` — **warned against**) |
| `--payload` | Payload name for the inject phase |
| `--i-understand-the-risks` | Mandatory acknowledgment for write phases |

### Safety Interlocks

1. **`--i-understand-the-risks`** — the `flash` and `recover` phases refuse to run without this explicit flag. It acknowledges the brick risk documented in LAB_TESTING.md.
2. **`SIMULATION` environment variable** — write phases refuse to run unless `SIMULATION` is set:
   - `SIMULATION=1` — simulation mode: flashrom performs read-back verification only, **nothing is written**. Use this to rehearse the full phase flow safely.
   - `SIMULATION=0` — real-hardware mode: destructive writes proceed.
3. **Programmer warning** — the default `internal` programmer triggers a prominent warning recommending an external programmer (`ch341a_spi`, `dediprog`), because internal writes are blocked on locked flashes and offer no out-of-band recovery path.
4. **Backup enforcement** — `flash` and `recover` require an existing `--backup` file; there is no bypass.
5. **Safety banner** — every invocation prints the brick-risk banner from LAB_TESTING.md before doing anything.

---

## 🔬 jtag-monitor.sh — Debug Interface Capture

Captures JTAG/SWD activity during a test run using OpenOCD:

```bash
./jtag-monitor.sh --config board/custom-target.cfg --duration 300 --output traces/boot-trace.log
```

| Option | Purpose |
|--------|---------|
| `--config` | OpenOCD configuration file for probe + target (required) |
| `--duration` | Capture length in seconds (default 60) |
| `--output` | Trace output file (default `jtag-trace.log`) |

The script verifies `openocd` exists, runs it with `debug_level 3` for the capture window, and produces a transcript of target DAP/AP enumeration, halt/resume events, and memory/register accesses. The trace integrates with the **`debug_interface` detector**: unexpected probe activity during a boot under test (halts, debug-port reads) is an artifact the detector consumes — e.g. for detecting debug-interface abuse during implant installation. Requires a supported debug probe (FTDI/FT2232-based, ST-Link, J-Link) and correct wiring; see the equipment table in [LAB_TESTING.md](LAB_TESTING.md).

---

## 🔗 Integration with flashrom / chipsec

The HIL runner composes with the tooling LAB_TESTING.md already documents:

| Tool | Role in the HIL flow |
|------|----------------------|
| `flashrom` | All chip I/O — the runner only orchestrates `-r`/`-w`/`-v` invocations |
| `chipsec` | Pre-flight checks between phases: `common.bios_wp`, `common.smm`, Boot Guard / PSB status (MSR 0x13A) — run these manually before the first `flash` |
| `ifdtool` | Inspecting region layout of the backup before injecting into specific regions |
| `barzakh-adversary` | Phase 2 payload generation (`inject-single`) |
| `barzakh-scanner` | Phase 4 verification scans and reports |

Recommended pre-flight sequence before the first `flash` on any new board:

```bash
sudo python chipsec_main.py -m common.bios_wp       # write protection state
sudo python chipsec_main.py -m common.cpu.ia_untrusted  # Boot Guard status
ifdtool -d fw-backup.bin                            # region layout
```

If Boot Guard / PSB is provisioned, modified images will **never** execute — stop at Phase 2 (analysis only), as LAB_TESTING.md Phase 3+ requires.

---

## 🔄 How HIL Results Feed the Scanner and Knowledge Base

1. **`verify` produces reports** — JSON + HTML land in `test/hil/` (`hil-report.json`, `hil-report.html`)
2. **Record the platform** — every verify run reminds you to file the image in the KB:
   ```bash
   barzakh-scanner kb add --image test/hil/injected.bin --vendor ASUS \
       --device "PRIME Z690-A" --notes "HIL phase 4 after acpi_backdoor injection"
   ```
   See [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) for the profile schema and collaborative sharing.
3. **Detector tuning** — HIL results against *real* platform layouts are the ground truth the virtualization path cannot provide: non-standard flash layouts, OEM memory holes, locked SMRAM. Feed misses back into detector development (UC-D5 in [USECASES.md](USECASES.md)).
4. **Debug traces** — `jtag-monitor.sh` output is consumed by the `debug_interface` detector as run-time evidence, complementing static analysis of the flashed image.

---

## 🩹 Recovery Procedures

The runner's `recover` phase wraps the manual procedures from LAB_TESTING.md:

```bash
# Machine won't POST after a flash? Don't panic.
# 1. Power off completely, re-seat the SOIC clip (pin 1 alignment)
# 2. Confirm chip communication:
flashrom -p ch341a_spi --flash-name
# 3. Restore:
SIMULATION=0 ./hil-runner.sh --phase recover --backup fw-backup.bin \
    --programmer ch341a_spi --i-understand-the-risks
# 4. Remove clip, boot
```

Additional scenarios (ME region corruption with 30-minute boot delay, partial writes from a slipped clip, boot loops) are covered in the [Recovery Procedures section of LAB_TESTING.md](LAB_TESTING.md#-recovery-procedures).

**Standing rules:**

- Always keep the backup on separate media (USB + network share) — a backup that dies with the machine is not a backup
- Never remove the clip or cut power mid-write
- First boot after ME-region recovery may take ~30 minutes; wait it out

---

## 📚 Related

- [LAB_TESTING.md](LAB_TESTING.md) — the 5-phase progression, equipment list, safety prerequisites
- [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) — firmware profiles
- [USECASES.md](USECASES.md) — red/blue team use cases
- [README](../README.md) — project overview
