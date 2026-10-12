# Barzakh: Real Hardware Lab Testing Guide

> **Last Updated:** 2026-06-22 | **Applies to:** Ring -3 offense/defense modules

---

## ⚠️ Critical Warnings

**READ THIS ENTIRE SECTION BEFORE PROCEEDING.**

| Risk | Description |
|------|-------------|
| **Hardware Brick** | Incorrect SPI flash writes can permanently brick the motherboard. Recovery requires an external programmer and a known-good firmware image. |
| **Warranty Void** | Opening the chassis, attaching a flash programmer, or modifying firmware voids manufacturer warranty on all tested hardware. |
| **Legal Liability** | Modifying firmware on systems you do not own is a criminal offense in most jurisdictions. Even on owned hardware, some regions restrict firmware modification tools. |
| **Data Loss** | A failed flash can destroy NVRAM (UEFI variables, BitLocker keys, Secure Boot keys). Back up everything before starting. |
| **Intel ME / AMD PSP Damage** | Corrupting the Management Engine or Platform Security Processor region can cause irreversible 30-minute boot delays, permanent ME disable, or total board failure requiring RMA. |

**This guide assumes you are working on a dedicated, sacrificial test machine in an air-gapped lab. Never perform these procedures on production hardware, shared infrastructure, or machines containing important data.**

---

## 🔧 Lab Hardware Requirements

| Item | Purpose | What Happens Without It |
|------|---------|------------------------|
| Dedicated test machine (Intel Skylake+ or AMD Zen+) | Target for firmware operations | Cannot test platform-specific ME/PSP detectors |
| SPI flash programmer (CH341A ~$5, or Dediprog SF600 ~$400) | External read/write of SPI flash chip | **No recovery path** if firmware is corrupted — machine becomes a brick |
| SOIC-8 or SOIC-16 test clip | In-circuit connection to flash chip without desoldering | Must desolder the chip for every read/write (slow, risks pad damage) |
| USB-to-UART adapter (FTDI FT232R or CP2102) | Serial console output from firmware | No visibility into boot process — debugging becomes guesswork |
| Second machine (control station) | Run flashrom, analyze dumps, store backups | Single point of failure if test machine is also the recovery station |
| Isolated network switch | AMT SOL testing over dedicated VLAN | AMT traffic leaks to production network (security/compliance violation) |
| Multimeter | Verify 3.3V SPI voltage, check clip connections | Risk of applying wrong voltage or incomplete connection during flash |
| **Optional:** Logic analyzer (Saleae, DSLogic) | Debug SPI bus timing issues | Cannot diagnose intermittent flash failures |
| **Optional:** JTAG/SWD debugger | Deep platform debug (Intel DCI, AMD HDT) | Limited to black-box observation of boot behavior |

### Minimum Budget Breakdown

| Tier | Total Cost | Components |
|------|-----------|------------|
| Budget | ~$50 | CH341A + SOIC-8 clip + CP2102 + spare test machine (recycled) |
| Professional | ~$700 | Dediprog SF600 + Pomona clip + FTDI + logic analyzer |
| Full Lab | ~$2000+ | Above + multiple test platforms (Intel/AMD) + KVM switch + rack |

---

## 📋 Safety Prerequisites

Complete **every** step below before any destructive testing. These are not optional.

### Step 1: Dump Original Firmware via External Programmer

Connect the SPI programmer to the flash chip using the SOIC clip, then read the full image:

```bash
# CH341A example (most common budget programmer)
flashrom -p ch341a_spi -r original_firmware.bin

# Dediprog SF600
flashrom -p dediprog -r original_firmware.bin

# ALWAYS read twice and compare checksums
flashrom -p ch341a_spi -r original_firmware_verify.bin
sha256sum original_firmware.bin original_firmware_verify.bin
```

**⚠️ What happens if you skip this:** You have no recovery image. Any flash corruption means the machine is permanently bricked. There is no software-only recovery path once the SPI flash is corrupted — the chip must be reprogrammed externally.

**⚠️ Why read twice:** SPI clip connections are unreliable. A single bit flip in the dump means your "backup" is corrupt. If both reads produce identical SHA-256 hashes, the dump is trustworthy.

---

### Step 2: Verify External Reflash Works (Round-Trip Test)

```bash
# Write your dump back and verify it matches
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
```

Then **boot the machine** and confirm it starts normally.

**⚠️ What happens if you skip this:** You assume your programmer/clip setup works, but you've never proven it. If the clip has a bad connection on pin 3 (MOSI), writes silently corrupt data. You discover this only after flashing a modified image and failing to recover.

---

### Step 3: Check Intel Boot Guard / AMD PSB Status

```bash
# Using chipsec (requires Linux with kernel module)
sudo python chipsec_main.py -m common.bios_wp
sudo python chipsec_main.py -m common.secureboot.variables

# Check Boot Guard specifically
sudo python chipsec_main.py -m common.cpu.ia_untrusted

# Or examine the firmware image directly
ifdtool -x original_firmware.bin
```

**⚠️ What happens if you skip this:** If Intel Boot Guard is provisioned (fuses blown in the PCH), the CPU will **refuse to execute** any firmware not signed with the OEM's key. You flash a modified image, the machine appears dead (no POST, no beep, no serial output), and you waste hours debugging what is actually a cryptographic lockout. The machine still boots fine when you reflash the original — but modified images will **never** work on Boot Guard-enabled hardware.

**Key indicators:**

| Platform | Check | Boot Guard Active |
|----------|-------|-------------------|
| Intel | `MSR 0x13A` bit 0 | If set, Boot Guard fuses are blown |
| Intel | ACM (Authenticated Code Module) present in flash | OEM has provisioned verified boot |
| AMD | PSB fuse check via `chipsec` | Platform Secure Boot enabled |

**If Boot Guard/PSB is enabled:** You can still run Phase 1 and Phase 2 (analysis only). Phase 3-5 require either a Boot Guard-disabled board or signing your test images with the OEM key (not possible without the private key).

---

### Step 4: Document Platform Details

Record the following before any modifications:

```bash
# BIOS version
sudo dmidecode -t bios

# Board model
sudo dmidecode -t baseboard

# ME version (Intel)
sudo python chipsec_main.py -m common.me

# Full SMBIOS dump
sudo dmidecode > platform_info.txt

# SPI flash chip identification
flashrom -p ch341a_spi --flash-name
```

Store this in your lab notebook. If you need vendor support or a replacement BIOS image, you'll need the exact model, revision, and firmware version.

**⚠️ What happens if you skip this:** You corrupt the ME region and need the vendor's original ME firmware binary. Without the exact board model and BIOS version, you download the wrong image. Flashing a mismatched ME version causes additional failures.

---

### Step 5: Prepare Recovery Media

```bash
# Store multiple copies of the original dump
cp original_firmware.bin /mnt/usb_backup/
cp original_firmware.bin /mnt/network_share/

# Create a recovery script
cat > recover.sh << 'EOF'
#!/bin/bash
echo "=== EMERGENCY RECOVERY ==="
echo "Ensure SOIC clip is properly seated"
read -p "Press Enter to begin recovery flash..."
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
echo "Verification complete. Check output above for errors."
EOF
chmod +x recover.sh
```

**⚠️ What happens if you skip this:** Under pressure (machine won't POST, deadline approaching), you mistype a flashrom command or grab the wrong file. A pre-written recovery script eliminates human error during the most stressful moment.

---

## 🔒 Kill-Switch Mechanisms — Detailed Architecture

The Barzakh bootkit implements a **fail-closed, sequential kill-switch chain** at DXE driver entry. Every time the DXE module loads, `ValidateKillSwitches()` executes a series of hardware-bound and time-bound checks. If **any single check fails**, the module immediately returns `EFI_ABORTED` and the payload never executes.

This is not a software flag — it is a hard architectural gate enforced before any hooking, injection, or persistence logic runs.

---

### Kill-Switch Validation Flow

```
DXE Driver Entry Point
       │
       ▼
┌─────────────────────────┐
│  ValidateKillSwitches() │  ← Master orchestrator (KillSwitch.c:40-79)
└────────────┬────────────┘
             │
    ┌────────▼────────┐     FAIL → EFI_ABORTED (KillSwitchUuidMismatch)
    │ 1. UUID Binding │
    └────────┬────────┘
             │ PASS
    ┌────────▼────────┐     FAIL → EFI_ABORTED (KillSwitchTpmMismatch)
    │ 2. TPM EK Pin   │
    └────────┬────────┘
             │ PASS
    ┌────────▼────────┐     FAIL → EFI_ABORTED (KillSwitchExpired)
    │ 3. Time-Bomb    │
    └────────┬────────┘
             │ PASS
             ▼
     Module executes normally
```

**Result Codes** (defined in `KillSwitch.h`):

| Enum Value | Name | Meaning |
|------------|------|---------|
| 0 | `KillSwitchSuccess` | All checks passed |
| 1 | `KillSwitchUuidMismatch` | Hardware UUID does not match allowed value |
| 2 | `KillSwitchTpmMismatch` | TPM Endorsement Key hash mismatch |
| 3 | `KillSwitchExpired` | Time-bomb expiry date has passed |
| 4 | `KillSwitchError` | Internal error (protocol not found, etc.) |

---

### Kill Switch 1: SMBIOS UUID Hardware Binding

**Source:** `src/BootkitPkg/DxeInject/KillSwitch.c` — `ValidateUuid()` (lines 88–175)

**Purpose:** Ensures the bootkit only executes on a specific, pre-authorized physical machine. The module reads the system's SMBIOS Type 1 (System Information) table and compares the 16-byte UUID field against a compile-time or environment-configured allowed UUID.

#### How It Works

1. Locates the `EFI_SMBIOS_PROTOCOL` via `gBS->LocateProtocol()`
2. Iterates SMBIOS tables to find Type 1 (System Information)
3. Extracts the 16-byte UUID at the fixed offset in the Type 1 structure
4. Parses the allowed UUID string (`BARZAKH_ALLOWED_UUID`) from `"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"` format into raw bytes via `ParseUuidString()`
5. Performs a raw 16-byte `CompareMem()` comparison
6. Returns `FALSE` (kill) if bytes differ

#### Configuration

```bash
# Get your test machine's UUID
sudo dmidecode -s system-uuid
# Example output: 4C4C4544-0044-3710-8052-B5C04F385731

# Set in .env or export before build
export BARZAKH_ALLOWED_UUID="4C4C4544-0044-3710-8052-B5C04F385731"
```

**Compile-time define:** If `BARZAKH_ALLOWED_UUID` is not set, defaults to `"00000000-0000-0000-0000-000000000000"` — which will **never match** real hardware (fail-closed).

#### QEMU Testing

```bash
# QEMU passes UUID via -uuid flag (handled by qemu-run.sh automatically)
qemu-system-x86_64 ... -uuid "4C4C4544-0044-3710-8052-B5C04F385731"
```

The `scripts/qemu-run.sh` script reads `BARZAKH_ALLOWED_UUID` from the environment and passes it as the VM UUID:
```bash
VM_UUID="${BARZAKH_ALLOWED_UUID:-00000000-0000-0000-0000-000000000000}"
qemu-system-x86_64 ... -uuid "$VM_UUID"
```

#### Failure Behavior

- **Serial output:** `[BARZAKH] UUID validation FAILED - hardware mismatch`
- **Return:** `KillSwitchUuidMismatch` (enum value 1)
- **Effect:** Module aborts immediately, no further checks run

#### Lab Verification Procedure

```bash
# Test 1: Matching UUID (should PASS)
export BARZAKH_ALLOWED_UUID="$(sudo dmidecode -s system-uuid)"
./scripts/qemu-run.sh --debug --serial-log /tmp/ks-test-pass.log
grep "UUID validation" /tmp/ks-test-pass.log
# Expected: [BARZAKH] UUID validation PASSED

# Test 2: Mismatched UUID (should FAIL)
export BARZAKH_ALLOWED_UUID="DEADBEEF-DEAD-BEEF-DEAD-BEEFDEADBEEF"
./scripts/qemu-run.sh --debug --serial-log /tmp/ks-test-fail.log
grep "UUID validation" /tmp/ks-test-fail.log
# Expected: [BARZAKH] UUID validation FAILED - hardware mismatch

# Test 3: Default/unset UUID (should FAIL on real hardware)
unset BARZAKH_ALLOWED_UUID
./scripts/qemu-run.sh --debug --serial-log /tmp/ks-test-default.log
grep "UUID validation" /tmp/ks-test-default.log
# Expected: FAILED (00000000-... never matches real HW)
```

---

### Kill Switch 2: TPM Endorsement Key Pinning

**Source:** `src/BootkitPkg/DxeInject/TpmKillSwitch.c` — `ValidateTpmEndorsementKey()` (lines 80–135)

**Purpose:** Cryptographically binds execution to a specific TPM chip. Each TPM has a unique, non-clonable Endorsement Key (EK) burned at manufacture. The module reads the EK via `Tpm2ReadPublic()` and compares it against an expected value.

#### How It Works

1. `InitializeTpmKillSwitch()` locates the `EFI_TCG2_PROTOCOL` via `gBS->LocateProtocol()`
2. If no TCG2 protocol is found → returns `EFI_SECURITY_VIOLATION` (no TPM = no execution)
3. `ValidateTpmEndorsementKey()` calls `Tpm2ReadPublic(TPM_RH_ENDORSEMENT, ...)` to read the actual EK
4. Compares the actual EK size and content against `TPM_EXPECTED_EK` structure (256-byte RSA-2048 key)
5. Returns `TpmKillSwitchEkMismatch` if size or content differs

#### Advanced TPM Kill-Switches

Beyond basic EK pinning, the TPM module implements two additional mechanisms:

**Monotonic Counter (lines 144–187):**
```c
CheckTpmMonotonicCounter(ExpiryValue)
```
- Reads an NV-stored hardware counter via `Tpm2NvReadCounter()`
- Counter can only increment, never reset (hardware guarantee)
- If counter ≥ `TPM_EXPIRY_COUNTER` (default: 1,000,000), execution is killed
- **Use case:** Limits total number of boot cycles regardless of clock manipulation

**Signed Timestamp Validation (lines 198–264):**
```c
ValidateSignedTimestamp(Timestamp, Signature, SignatureSize)
```
- Verifies an RSA-SHA256 signature over a server-provided timestamp
- Uses `BARZAKH_SERVER_PUBLIC_KEY` (RSA-2048, defined in `TpmKillSwitch.h`)
- **5-minute future tolerance:** Rejects timestamps >5 minutes in the future (clock skew protection)
- **24-hour expiry window:** Rejects timestamps older than 24 hours
- **Fail-closed crypto:** Without `BARZAKH_STUB_CRYPTO` defined, the `RsaVerify()` stub rejects ALL signatures

#### TPM Kill-Switch Result Codes

| Enum Value | Name | Meaning |
|------------|------|---------|
| 0 | `TpmKillSwitchSuccess` | TPM validation passed |
| 1 | `TpmKillSwitchNoTpm` | TCG2 protocol not found |
| 2 | `TpmKillSwitchEkMismatch` | EK does not match expected |
| 3 | `TpmKillSwitchCounterExpired` | Monotonic counter exceeded threshold |
| 4 | `TpmKillSwitchError` | Internal error |

#### Configuration

```bash
# Read your TPM's Endorsement Key
sudo tpm2_readpublic -c 0x81010001 -o /tmp/ek.pub

# Get the SHA-256 hash for documentation
sha256sum /tmp/ek.pub

# The raw EK bytes must be compiled into TPM_EXPECTED_EK in TpmKillSwitch.h
# See SETUP.md Section 6.4 for the full procedure
```

**Constants** (defined in `TpmKillSwitch.h`):

| Constant | Value | Purpose |
|----------|-------|---------|
| `TPM_EK_SIZE` | 256 | RSA-2048 key size in bytes |
| `TPM_EXPIRY_COUNTER` | 1,000,000 | Maximum allowed boot cycles |
| `BARZAKH_SERVER_PUBLIC_KEY[256]` | RSA-2048 placeholder | Server's public key for timestamp verification |

#### QEMU Mode Bypass

When compiled with `BARZAKH_QEMU_MODE`, the TPM kill-switch has a fallback:

```c
#ifdef BARZAKH_QEMU_MODE
    // In QEMU mode, TPM failure is non-fatal (vTPM may not be configured)
    if (TpmResult == TpmKillSwitchNoTpm) {
        DEBUG((DEBUG_WARN, "[BARZAKH] QEMU mode: TPM not available, bypassing\n"));
        // Continue execution — UUID and time-bomb still enforced
    }
#endif
```

This allows testing without a vTPM configured, but **UUID and time-bomb checks still apply**.

#### Lab Verification Procedure

```bash
# Test 1: With vTPM configured (should PASS if EK matches)
swtpm socket --tpmstate dir=~/barzakh-workspace/vtpm-state \
    --ctrl type=unixio,path=~/barzakh-workspace/vtpm-state/swtpm-sock \
    --tpm2 --daemon
./scripts/qemu-run.sh --debug --serial-log /tmp/tpm-test.log
grep "TPM" /tmp/tpm-test.log
# Expected: [BARZAKH] TPM EK validation PASSED

# Test 2: Without vTPM (QEMU mode — should bypass with warning)
# Build with: -D BARZAKH_QEMU_MODE
pkill swtpm
./scripts/qemu-run.sh --debug --serial-log /tmp/tpm-bypass.log
grep "TPM" /tmp/tpm-bypass.log
# Expected: [BARZAKH] QEMU mode: TPM not available, bypassing

# Test 3: Without vTPM (production mode — should FAIL)
# Build WITHOUT BARZAKH_QEMU_MODE
pkill swtpm
./scripts/qemu-run.sh --debug --serial-log /tmp/tpm-fail.log
grep "TPM" /tmp/tpm-fail.log
# Expected: [BARZAKH] TPM validation FAILED - no TCG2 protocol
```

---

### Kill Switch 3: Time-Bomb Expiry

**Source:** `src/BootkitPkg/DxeInject/KillSwitch.c` — `ValidateExpiry()` (lines 233–296)

**Purpose:** Ensures the module self-destructs (refuses to run) after a fixed date. Even if the binary persists on flash, it becomes inert once the expiry date passes. This prevents indefinite persistence in case of a lost or stolen test machine.

#### How It Works

1. Calls `gRT->GetTime()` to read the system's real-time clock (RTC)
2. Parses `BARZAKH_EXPIRY_DATE` string from `"YYYY-MM-DD"` format via `ParseDateString()`
3. Calls `CompareDates()` to compare current date against expiry
4. Returns `FALSE` (kill) if `current_date >= expiry_date`

#### Date Comparison Logic

```c
// CompareDates returns:
//   -1 if date1 < date2
//    0 if date1 == date2
//    1 if date1 > date2
//
// ValidateExpiry kills if CompareDates(current, expiry) >= 0
// i.e., expiry date has arrived or passed
```

#### Configuration

```bash
# Set expiry date (must be YYYY-MM-DD format)
export BARZAKH_EXPIRY_DATE="2027-12-31"

# This becomes a compile-time define passed to the UEFI build:
# -D BARZAKH_EXPIRY_DATE="2027-12-31"
```

**Default:** If `BARZAKH_EXPIRY_DATE` is not set, defaults to `"2027-12-31"`.

#### Failure Behavior

- **Serial output:** `[BARZAKH] Expiry validation FAILED - module expired`
- **Return:** `KillSwitchExpired` (enum value 3)
- **Effect:** Module aborts, payload never executes

#### Important Notes

- **RTC dependency:** This relies on the system's real-time clock. An attacker with physical access could set the BIOS clock backward. However, the TPM monotonic counter (Kill Switch 2) provides a secondary bound that is immune to clock manipulation.
- **Granularity:** Date-level only (no hours/minutes). The module expires at the start of the expiry day.
- **No network required:** The check is purely local RTC — works in air-gapped environments.

#### Lab Verification Procedure

```bash
# Test 1: Current date before expiry (should PASS)
export BARZAKH_EXPIRY_DATE="2030-12-31"
./scripts/qemu-run.sh --debug --serial-log /tmp/expiry-pass.log
grep "Expiry" /tmp/expiry-pass.log
# Expected: [BARZAKH] Expiry validation PASSED

# Test 2: Expired date (should FAIL)
export BARZAKH_EXPIRY_DATE="2020-01-01"
./scripts/qemu-run.sh --debug --serial-log /tmp/expiry-fail.log
grep "Expiry" /tmp/expiry-fail.log
# Expected: [BARZAKH] Expiry validation FAILED - module expired

# Test 3: Expiry today (should FAIL — "on or after" semantics)
export BARZAKH_EXPIRY_DATE="$(date +%Y-%m-%d)"
./scripts/qemu-run.sh --debug --serial-log /tmp/expiry-today.log
grep "Expiry" /tmp/expiry-today.log
# Expected: [BARZAKH] Expiry validation FAILED - module expired
```

---

### Kill Switch 4: Air-Gap Enforcement

**Purpose:** Detects the presence of network interfaces at DXE phase and refuses execution if networking hardware is active. This enforces the air-gap requirement at the firmware level — even if an operator forgets to physically disconnect the cable.

#### How It Works

- Enumerates PCI devices looking for network controller class codes (Class 02h)
- If any network interface is found in an enabled/active state, the kill-switch fires
- Operates at DXE phase before any OS-level network stack loads

#### Configuration

Network enforcement is always-on when compiled without `BARZAKH_QEMU_MODE`. In QEMU mode, the `--no-network` flag (default in `qemu-run.sh`) ensures no virtual NIC is attached to the VM.

#### Lab Verification Procedure

```bash
# Test 1: No network device (should PASS)
./scripts/qemu-run.sh --no-network --debug --serial-log /tmp/airgap-pass.log
grep -i "network\|air.gap" /tmp/airgap-pass.log
# Expected: No network-related kill-switch failure

# Test 2: With network device attached (may trigger depending on build)
# WARNING: Only test this in QEMU, never on physical hardware in production
qemu-system-x86_64 ... -netdev user,id=net0 -device virtio-net-pci,netdev=net0
# Check serial log for air-gap violation message
```

---

### Kill Switch 5: SIMULATION_MODE Flag

**Purpose:** A global compile-time flag that prevents any real hardware operations. When `SIMULATION_MODE` is active, all hardware-modifying DXE operations become no-ops — no persistence writes, no SPI flash operations, no MSR writes. Boot Services hooks still install (they are the detection target) but their side effects are logged only.

Since the mode unification, the flag lives in **`src/BootkitPkg/Include/BarzakhMode.h`** and is controlled by a single build define — no per-module flags.

#### How It Works

- `BARZAKH_SIMULATION_MODE` (aliased as `SIMULATION_MODE`) is defined centrally in `BarzakhMode.h`
- It is checked at the top of each hardware-modifying function
- If set, functions log the operation and return success without performing it
- Allows running the full DXE module logic path for testing while guaranteeing zero hardware modification
- Functional (real-hardware) builds require **both** `-DBARZAKH_FUNCTIONAL=1` and the existing `BARZAKH_RESEARCH` gate — a functional build without the research gate fails to compile

#### When SIMULATION_MODE Is Active

| Operation | Behavior |
|-----------|----------|
| SPI flash writes | Skipped (logged) |
| MSR hooking | Writes skipped (reads still real) |
| FVB2 flash programming | Never invoked |
| PCI ROM BAR injection | Skipped (logged) |
| NVRAM variable writes | Skipped (logged) |
| Serial debug output | Still active (read-only) |

#### What a Functional Build Changes

| Path | Simulation | Functional (`-DBARZAKH_FUNCTIONAL=1`) |
|------|------------|----------------------------------------|
| SPI flash write/erase | In-RAM shadow buffer only | Routed through `EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL` (real LoJax-style persistence path) |
| PCI option ROM injection | Fabricated device list, logged only | Real `PciRead/PciWrite` enumeration + MMIO ROM BAR write |
| MSR writes (IA32_LSTAR etc.) | Logged only | Real `AsmWriteMsr64` |

**Build commands:**

```bash
# Simulation build (default — what CI builds and publishes)
build -a X64 -t GCC5 -p BootkitPkg/BootkitPkg.dsc

# Functional lab build (research gate required, never publish)
build -a X64 -t GCC5 -p BootkitPkg/BootkitPkg.dsc \
    -D BARZAKH_FUNCTIONAL=1
```

The functional define can also be uncommented in the DSC `[BuildOptions]` section, but the command-line form is preferred so published builds never carry it.

#### Lab Verification Procedure

```bash
# Build with SIMULATION_MODE enabled (default)
# Then run normally — check serial output confirms no-op behavior
./scripts/qemu-run.sh --debug --serial-log /tmp/sim-mode.log
grep "SIMULATION" /tmp/sim-mode.log
# Expected: [SPI-Emu] SIMULATION: Would write ... (and similar)

# Functional build in QEMU (OVMF's FVB2 protocol is real, writes go
# to the emulated pflash backend — safe rehearsal for hardware)
# Then verify writes actually landed:
grep "FUNCTIONAL BUILD: real flash writes ENABLED" /tmp/serial.log
```

---

### Compile-Time Flags Summary

| Flag | Effect | Default |
|------|--------|---------|
| `BARZAKH_ALLOWED_UUID` | 36-char UUID string for hardware binding | `"00000000-0000-0000-0000-000000000000"` (never matches) |
| `BARZAKH_EXPIRY_DATE` | `"YYYY-MM-DD"` expiry date | `"2027-12-31"` |
| `BARZAKH_QEMU_MODE` | Allows TPM bypass, relaxes air-gap check | Not defined (strict mode) |
| `BARZAKH_STUB_CRYPTO` | Enables stub RSA verification (testing only) | Not defined (fail-closed) |
| `BARZAKH_FUNCTIONAL` | Enables real hardware paths (FVB2 flash, ROM BAR injection, MSR writes). Requires `BARZAKH_RESEARCH` | Not defined (simulation mode) |

---

### Environment Variables for Lab Configuration

| Variable | Purpose | How to Obtain |
|----------|---------|---------------|
| `BARZAKH_ALLOWED_UUID` | Machine UUID for binding | `sudo dmidecode -s system-uuid` |
| `BARZAKH_EXPIRY_DATE` | Project expiry date | Set per institutional policy |
| `PROJECT_START_DATE` | Audit trail reference | Set at project initiation |

---

### Kill-Switch Testing Checklist

Before proceeding to any live testing phase, verify each kill-switch independently:

- [ ] **UUID Kill-Switch:** Confirmed module aborts with mismatched UUID
- [ ] **UUID Kill-Switch:** Confirmed module passes with correct UUID
- [ ] **TPM Kill-Switch:** Confirmed module aborts without TPM (production build)
- [ ] **TPM Kill-Switch:** Confirmed QEMU bypass works (QEMU build)
- [ ] **Time-Bomb:** Confirmed module aborts with past expiry date
- [ ] **Time-Bomb:** Confirmed module passes with future expiry date
- [ ] **Air-Gap:** Confirmed no network interfaces attached in test VM
- [ ] **SIMULATION_MODE:** Confirmed no hardware writes occur when enabled
- [ ] **Fail-Closed Default:** Confirmed module aborts with all-zeros UUID (unconfigured state)
- [ ] **Serial Logging:** Confirmed all kill-switch results appear in serial output

**⚠️ CRITICAL:** Never proceed to Phase 3+ testing without completing this checklist. The kill-switches are your primary safety mechanism against uncontrolled execution.

---

## 🧪 Test Progression

### Phase 1: Non-Destructive Firmware Analysis

**Risk Level: None** — All operations are read-only against a file on your control station.

#### What You Do

```bash
# Scan the real firmware dump with Barzakh
cd src/barzakh-scanner-rs
cargo build --release
./target/release/barzakh-scanner scan --target /path/to/original_firmware.bin
./target/release/barzakh-scanner report --target /path/to/original_firmware.bin --format html --output real_hw_report.html

# Run with all detectors explicitly
./target/release/barzakh-scanner scan --target /path/to/original_firmware.bin --scan-types all
```

#### What Happens

The scanner reads the binary file you provide. It never opens hardware devices, never writes to disk (other than the report file), and never modifies the input. This is equivalent to running `strings` or `hexdump` on the file — purely passive analysis.

**Expected results on clean firmware:**
- 0-3 Low/Medium findings (normal — some vendors ship with FLOCKDN not set in the image, or have unusual ACPI table counts)
- Any Critical/High findings on stock firmware indicate either a pre-existing compromise or a false positive worth investigating

#### What You Learn

- Whether your real hardware's firmware has any suspicious artifacts before you modify it
- Baseline finding count for comparison after testing
- Whether any detectors produce false positives on your specific platform's firmware

---

### Phase 2: Adversary Payload Validation Against Real Images

**Risk Level: None** — All operations happen on files on your control station. No hardware interaction.

#### What You Do

```bash
# Generate tampered versions of your real firmware dump
cd src/barzakh-scanner-rs
cargo test -p barzakh-adversary -- --ignored corpus_validation

# Or use the standalone barzakh-adversary binary
cp /path/to/original_firmware.bin /tmp/test_image.bin

# Run the adversary payloads against the real image structure
./target/release/barzakh-adversary generate --input /tmp/test_image.bin --output /tmp/tampered/

# Scan all tampered images
for img in /tmp/tampered/*.bin; do
    echo "=== Scanning: $img ==="
    ./target/release/barzakh-scanner scan --target "$img" --report
done
```

#### What Happens

The adversary tool reads your real firmware dump, injects known-bad patterns (corrupted ACPI checksums, fake ME region overlaps, suspicious SMM handler patterns), and writes modified copies to your output directory. The scanner then analyzes these modified copies.

**No hardware is involved.** The test machine remains untouched. You are validating that Barzakh's detectors can find implants in the specific binary layout of your real platform's firmware.

#### What You Learn

- Whether detectors work against your specific platform's firmware structure (some platforms have non-standard flash layouts that may confuse pattern matching)
- True positive rate on a realistic image rather than synthetic test data
- Which payloads are detectable and which might need detector tuning for your platform

---

### Phase 3: External Flash with Modified Images

**Risk Level: Medium** — You are writing to the SPI flash chip. The machine may fail to boot.

#### What You Do

```bash
# 1. Create a test image with a KNOWN, MINIMAL modification
cp original_firmware.bin test_phase3.bin

# Example: inject an ACPI checksum error (detectable, harmless to boot)
# Use barzakh-adversary to create a minimally modified image
cargo run -p barzakh-adversary -- inject-single \
    --input original_firmware.bin \
    --output test_phase3.bin \
    --payload acpi_backdoor

# 2. Flash the modified image via external programmer
flashrom -p ch341a_spi -w test_phase3.bin

# 3. Attempt to boot — observe serial console
# (Connect UART adapter, open minicom/screen on control station)
screen /dev/ttyUSB0 115200

# 4. After testing, IMMEDIATELY recover
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
```

#### What Happens

When you write the modified image:
- **flashrom erases the entire chip** (or affected sectors), then writes the new data, then optionally verifies
- The erase+write cycle takes 30-120 seconds depending on chip size (typically 8-32 MB)
- **If the clip loses contact during write:** Partial write = corrupted chip. The machine won't POST. Reflash with the original to recover.
- **If the modification corrupts a critical region (PEI/SEC volume):** Machine won't POST (black screen, no beep). This is expected. Reflash original to recover.
- **If only ACPI/BGRT/padding areas are modified:** Machine boots normally. You can then dump firmware from the running OS and scan it to validate detection works end-to-end.

#### Recovery

```bash
# Machine won't POST? Don't panic. External reflash:
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin
# If verify passes: remove clip, boot. Machine should recover.
```

**⚠️ Critical caution:** Never remove the SOIC clip while a flash operation is in progress. Wait for flashrom to report completion. Interrupting a write leaves the chip in an inconsistent state.

---

### Phase 4: Intel ME / AMD PSP Testing

**Risk Level: High** — Modifications to ME/PSP regions can cause irreversible platform behavior changes.

#### Intel ME Testing

```bash
# Extract ME region from firmware dump
ifdtool -x original_firmware.bin
# Produces: flashregion_2_intel_me.bin

# Analyze ME version and configuration
python me_analyzer.py flashregion_2_intel_me.bin

# Set HAP (High Assurance Platform) bit to disable ME post-boot
# WARNING: This is a ONE-WAY operation on some platforms
python me_cleaner.py -s -O modified_me.bin original_firmware.bin

# Flash the HAP-modified image
flashrom -p ch341a_spi -w modified_me.bin
```

#### What Happens When You Modify ME

| Action | Consequence | Reversible? |
|--------|-------------|-------------|
| Set HAP bit | ME initializes hardware then halts. AMT/vPro disabled. | Yes — reflash original ME region |
| Truncate ME region (me_cleaner -r) | ME fails to boot, enters recovery mode. 30-min boot delay on some platforms. | Yes — reflash original, but delay persists for one boot cycle |
| Zero-fill ME region | **Platform may not POST at all.** Intel CPU requires ME for power management initialization. | Yes — reflash, but some Skylake+ boards require specific ME recovery procedure |
| Corrupt ME partition table | ME enters manufacturing mode. All ME interfaces exposed. Security implications. | Yes — reflash original |

**⚠️ Critical:** On platforms where ME handles the initial power sequencing (Skylake and newer), a completely missing ME region means the CPU cannot initialize. The machine appears completely dead — no fans, no LED, nothing. This is NOT a brick; external reflash of the correct ME firmware restores it. But it is indistinguishable from hardware failure until you reflash.

#### AMD PSP Testing

```bash
# PSP firmware is embedded in the BIOS image
# Extract PSP directory using PSPTool
python psptool.py original_firmware.bin

# Examine fTPM firmware blob
python psptool.py --entry-type 0x07 original_firmware.bin
```

#### What Happens When You Modify PSP

| Action | Consequence | Reversible? |
|--------|-------------|-------------|
| Extract and re-inject PSP firmware | If signatures invalid, PSP refuses to boot. CPU halts. | Yes — reflash original |
| Modify fTPM blob | TPM becomes non-functional. BitLocker keys lost if sealed to TPM. | Yes — reflash, but sealed keys are gone |
| Enable PSP debug mode | Requires AMD-signed debug key (not publicly available) | N/A — cannot be done without AMD partnership |

**⚠️ AMD Platform Secure Boot:** If PSB fuses are blown (check with `chipsec`), any modification to the PSP region causes immediate boot failure. The CPU refuses to execute. Unlike Intel Boot Guard which only protects the IBB (Initial Boot Block), AMD PSB covers the entire PSP firmware.

#### HECI Bus Monitoring (Safe, Read-Only)

```bash
# Monitor HECI (Host Embedded Controller Interface) via PCI config space
# This is READ-ONLY observation — cannot damage hardware
sudo setpci -s 00:16.0 40.l  # HECI-1 base address
sudo python chipsec_main.py -m common.me

# Watch for ME-to-host communication patterns
sudo cat /dev/mei0 | xxd | head -100
```

**What happens:** Reading HECI/MEI device files is passive observation. The ME processes your read request and returns status data. No writes occur. This is safe on any platform regardless of Boot Guard status.

---

### Phase 5: Live Offense Module Testing

**Risk Level: Very High** — You are running actual DXE implants on real hardware. System crash is expected.

#### Prerequisites for Phase 5

- Completed Phases 1-3 successfully
- Boot Guard / PSB is NOT enabled (or you have signing keys)
- Secure Boot is disabled in UEFI settings
- Serial console connected and logging
- External programmer verified working (you WILL need recovery)

#### What You Do

```bash
# 1. Build in functional mode (single flag, no per-module edits)
source edksetup.sh
build -a X64 -t GCC5 -p BootkitPkg/BootkitPkg.dsc -D BARZAKH_FUNCTIONAL=1
# This routes SPI flash writes through the real FVB2 protocol,
# performs real PCI ROM BAR injection, and enables real MSR writes.

# 2. Inject built DXE drivers into firmware image
#    Use UEFITool to insert the .efi into a firmware volume
#    Or use FMMT (Firmware Module Management Tool)

# 3. Flash the complete image
flashrom -p ch341a_spi -w firmware_with_implants.bin

# 4. Boot and observe serial output
screen /dev/ttyUSB0 115200
# You should see DXE driver load messages and hook confirmations

# 5. IMMEDIATELY recover after testing
flashrom -p ch341a_spi -w original_firmware.bin
```

#### What Happens

When the machine boots with live offense modules:

| Module | Runtime Behavior | Likely Outcome |
|--------|-----------------|----------------|
| `spi_write_implant` | Attempts to write-protect SPI regions via HSFS register | May conflict with platform's existing SPI controller init — crash or hang during DXE |
| `dxe_persistence` | Hooks Boot Services table, installs notify callbacks | Works on most platforms but exact table offsets differ from OVMF — potential crash |
| `smm_callout` | Triggers SMI and attempts SMRAM access | Will be blocked by hardware SMRAM protection on modern platforms. TSEG lock causes immediate reset. |
| `me_heci_exfil` | Opens HECI channel to communicate with ME | ME may reject unauthorized HECI traffic. Unlikely to crash but returns error codes. |
| `amt_sol_pivot` | Attempts to establish Serial-over-LAN channel | Requires AMT to be provisioned and in the correct state. Fails gracefully if AMT not configured. |

**⚠️ Critical differences from QEMU/OVMF:**

1. **Memory map is different.** OVMF has a predictable memory layout. Real hardware has OEM-specific memory holes, reserved regions, and ME stolen memory. Hardcoded addresses will fault.
2. **SMM is actually protected.** QEMU doesn't enforce SMRAM boundaries. Real hardware has D_LCK set — any access to TSEG triggers immediate platform reset.
3. **DXE dispatch order varies.** On real hardware, other DXE drivers may have already claimed resources your implant expects. Race conditions that never happen in QEMU appear on real boards.
4. **Crash = no debug output.** In QEMU, a crash produces a stack trace. On real hardware, you see the serial output stop and the machine resets. You must infer the failure point from the last successful output line.

**Expected outcome for first attempt:** The machine boots partway, one of the implants faults due to an incorrect assumption about the platform, and the machine resets. This is normal. You iterate by examining serial output, identifying the failure, adjusting the module, and reflashing.

---

## 🔬 Module-Specific Testing Notes

### SPI/Flash Modules (`spi_write_implant`, `me_spi` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Fully testable with external programmer |
| Prerequisites | CH341A or Dediprog + SOIC clip |
| What to observe | Flash write-protect bits (HSFS/FRAP registers), descriptor lock (FLOCKDN) |
| Safe test method | Dump firmware, check FLOCKDN bit in image, compare against running platform's actual register state (via `chipsec`) |

### SMM Modules (`smm_callout`, `smm_timing` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Limited on modern hardware — TSEG is locked |
| Prerequisites | Older board with known SMM unlock (pre-2015 consumer boards) OR a debug platform |
| What to observe | D_LCK status, TSEG base/mask, SMI handler entry points |
| Safe test method | Run `chipsec_main.py -m common.smm` to check if SMRAM is actually locked. If locked, test only the detector against firmware dumps — live SMM access will trigger platform reset. |

### HECI/ME Modules (`me_heci_exfil`, `heci_comm` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Passive monitoring works everywhere; active HECI requires ME cooperation |
| Prerequisites | Platform with ME enabled, HECI device visible in PCI enumeration |
| What to observe | HECI message queues, ME firmware status register (FWSTS) |
| Safe test method | Read `/dev/mei0` and PCI config space. This is passive and cannot damage the platform. |

### AMT SOL Module (`amt_sol_pivot`)

| Aspect | Detail |
|--------|--------|
| Testability | Fully testable once AMT is provisioned |
| Prerequisites | Intel vPro platform with AMT, provisioned via MEBx (press Ctrl+P at boot) |
| What to observe | SOL session establishment, OOB data channel |
| Setup | Enter MEBx (Ctrl+P during POST), set password, enable AMT, configure network. Then from control station: `amtterm <target-ip>` |

### fTPM Module (`ftpm_extract` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Observation only — cannot modify PSP without AMD debug keys |
| Prerequisites | AMD Zen+ platform with fTPM enabled |
| What to observe | fTPM NV indices, sealed key states, PCR values |
| Safe test method | Use `tpm2-tools` to read TPM state: `tpm2_pcrread`, `tpm2_nvreadpublic`. Purely read-only. |

### DMA/IOMMU Module (`iommu_bypass` detector)

| Aspect | Detail |
|--------|--------|
| Testability | Observable via IOMMU logs; active testing requires Thunderbolt/PCIe device |
| Prerequisites | Platform with IOMMU enabled, DMA-capable expansion slot or Thunderbolt port |
| What to observe | IOMMU fault logs, DMA remapping table (DMAR) entries |
| Safe test method | Enable IOMMU verbose logging: `intel_iommu=on iommu=verbose` kernel params. Monitor `dmesg` for DMA translation faults. |

---

## 🔄 Recovery Procedures

### Scenario: Machine Won't POST After Flash

**Symptoms:** Power LED on, fans spin, but no video output, no beep codes, no serial output.

```bash
# 1. Power off completely (hold power 10s or disconnect AC)
# 2. Re-seat SOIC clip on flash chip
# 3. Verify clip connection:
flashrom -p ch341a_spi --flash-name
# Should report the chip model. If "No EEPROM/flash found", clip is not connected.

# 4. Reflash original firmware
flashrom -p ch341a_spi -w original_firmware.bin

# 5. Verify the write
flashrom -p ch341a_spi -v original_firmware.bin
# Must report "VERIFIED"

# 6. Remove clip, reconnect all cables, attempt boot
```

**If flashrom cannot detect the chip:** The clip is not making good contact. Clean the chip pins with isopropyl alcohol, re-seat the clip ensuring pin 1 alignment (dot on chip = red wire on clip), and retry.

---

### Scenario: ME Region Corrupted (30-Minute Boot Delay)

**Symptoms:** Machine eventually boots after ~30 minutes, or displays "ME in Recovery Mode" message.

```bash
# 1. Extract clean ME region from your original dump
ifdtool -x original_firmware.bin
# Produces flashregion_2_intel_me.bin

# 2. If you have a modified image that corrupted ME, rebuild it:
ifdtool -i ME:flashregion_2_intel_me.bin modified_firmware.bin -O repaired_firmware.bin

# 3. Or just reflash the entire original
flashrom -p ch341a_spi -w original_firmware.bin

# 4. After reflash, the FIRST boot may still show the 30-min delay
#    (ME needs one clean boot cycle to exit recovery state)
#    Wait for it. Subsequent boots will be normal.
```

---

### Scenario: Partial SPI Write (Clip Slipped During Flash)

**Symptoms:** flashrom reported an error mid-write. Machine state unknown.

```bash
# DO NOT attempt to boot. The image is partially written.

# 1. Verify you can still communicate with the chip
flashrom -p ch341a_spi --flash-name

# 2. If chip responds, do a FULL erase + write (not differential)
flashrom -p ch341a_spi -E  # Full erase
flashrom -p ch341a_spi -w original_firmware.bin
flashrom -p ch341a_spi -v original_firmware.bin

# 3. If chip does NOT respond:
#    - Check clip seating
#    - Check programmer power (some need external 3.3V)
#    - If chip is in a locked state, try: flashrom -p ch341a_spi --force
```

**⚠️ Caution:** A partial write that corrupted only the descriptor region may have changed the flash access permissions. The `--force` flag bypasses safety checks. Use only when normal recovery fails.

---

### Scenario: Boot Loop After Modification

**Symptoms:** Machine starts to boot, shows vendor logo or early POST, then resets. Repeats indefinitely.

```bash
# This usually means the DXE phase loads but a driver crashes.
# The platform resets via watchdog timer.

# Option A: Clear NVRAM to reset boot variables
# (If your firmware image has a separate NVRAM region)
# Extract layout:
ifdtool -x original_firmware.bin
# Identify NVRAM volume in UEFITool
# Zero-fill only the NVRAM FV, keep everything else from the image that was booting

# Option B: Just reflash original (simplest)
flashrom -p ch341a_spi -w original_firmware.bin
```

---

## 📖 Tool Reference

### flashrom — SPI Flash Read/Write/Verify

```bash
# Read entire flash chip to file
flashrom -p <programmer> -r <output.bin>

# Write file to flash chip (erases first)
flashrom -p <programmer> -w <input.bin>

# Verify flash contents match file
flashrom -p <programmer> -v <file.bin>

# Full chip erase
flashrom -p <programmer> -E

# Identify flash chip without read/write
flashrom -p <programmer> --flash-name

# Common programmers:
#   ch341a_spi      - CH341A USB programmer ($5)
#   dediprog        - Dediprog SF600 ($400)
#   linux_spi       - Raspberry Pi GPIO SPI (/dev/spidev0.0)
#   internal        - Read via CPU's SPI controller (read-only on locked systems)
```

### me_cleaner — Intel ME Manipulation

```bash
# Set HAP bit (disables ME after hardware init)
python me_cleaner.py -s -O output.bin input.bin

# Remove non-essential ME modules (aggressive)
python me_cleaner.py -r -O output.bin input.bin

# Show ME version and partition info
python me_cleaner.py -c input.bin
```

**⚠️ Caution:** me_cleaner modifies a FILE. It does not touch hardware directly. You must flash the output file using flashrom separately.

### UEFITool — Firmware Image Inspector

```bash
# GUI tool — open firmware images and inspect structure
UEFITool original_firmware.bin

# Key operations:
# - Extract specific firmware volumes or DXE drivers
# - Search for GUIDs, text strings, hex patterns
# - Insert/replace modules (for implant injection testing)
# - Validate image structure and checksums
```

### ifdtool — Intel Flash Descriptor Tool

```bash
# Extract all flash regions to separate files
ifdtool -x firmware.bin
# Produces: flashregion_0_flashdescriptor.bin
#           flashregion_1_bios.bin
#           flashregion_2_intel_me.bin
#           flashregion_3_gbe.bin

# Show flash descriptor layout
ifdtool -d firmware.bin

# Inject ME region from separate file
ifdtool -i ME:me_firmware.bin firmware.bin -O output.bin

# Unlock flash descriptor (remove region write protections)
ifdtool -u firmware.bin -O unlocked.bin
```

### chipsec — Platform Security Assessment

```bash
# Run all security checks
sudo python chipsec_main.py

# Check specific module:
sudo python chipsec_main.py -m common.bios_wp        # BIOS write protection
sudo python chipsec_main.py -m common.smm            # SMM protection (SMRAM)
sudo python chipsec_main.py -m common.spi_lock       # SPI flash lock status
sudo python chipsec_main.py -m common.secureboot     # Secure Boot status
sudo python chipsec_main.py -m common.me             # ME configuration

# Dump SPI flash via CPU (internal, read-only if locked)
sudo python chipsec_util.py spi dump spi_dump.bin

# Read specific MSR
sudo python chipsec_util.py msr 0x13A  # IA32_FEATURE_CONTROL (Boot Guard)
```

**⚠️ Caution:** chipsec requires a kernel module that grants ring-0 access. Installing `chipsec` on production systems creates a privilege escalation vector. Use only on dedicated test machines.

### barzakh-scanner — Firmware Threat Detection

```bash
# Scan a firmware dump
./target/release/barzakh-scanner scan --target firmware.bin

# Generate HTML report
./target/release/barzakh-scanner report --target firmware.bin --format html --output report.html

# Compare against baseline
./target/release/barzakh-scanner scan --target firmware.bin --baseline clean_baseline.json

# Scan with specific detector categories
./target/release/barzakh-scanner scan --target firmware.bin --scan-types spi,smm,acpi,me
```

### barzakh-adversary — Red-Team Payload Generator

```bash
# List all available payloads
./target/release/barzakh-adversary list

# Generate payloads for your target architecture
./target/release/barzakh-adversary generate --arch x86_64

# Generate a full test corpus (malicious + clean pairs)
./target/release/barzakh-adversary corpus --output ./corpus

# Validate detection rates against corpus
./target/release/barzakh-adversary validate --corpus ./corpus

# Boot a payload in QEMU for live observation
./target/release/barzakh-adversary qemu --payload trampoline

# Build ESP image for flashing to real hardware
./target/release/barzakh-adversary esp --payload dxe_persistence
```

---

## ⚖️ Legal & Ethical Notice

### Authorized Use Only

- **Only test on hardware you own** or have explicit written authorization to modify
- **Do not deploy** offense modules on production systems, enterprise infrastructure, or shared equipment
- **Do not distribute** modified firmware images containing implants
- **Air-gap the test environment** — no network connectivity between test machines and production networks (except isolated VLAN for AMT testing)

### Jurisdictional Considerations

| Region | Key Restriction |
|--------|----------------|
| USA | CFAA prohibits unauthorized access to computer systems. Firmware modification on owned hardware is legal, but distributing tools "primarily designed" for unauthorized access may violate DMCA §1201 |
| EU | Computer Misuse Directive (2013/40/EU). Similar to CFAA — authorized research is permitted, unauthorized modification is criminal |
| UK | Computer Misuse Act 1990. Explicit exemption for authorized security testing |
| India | IT Act 2000, Section 43/66. Unauthorized modification is punishable. Ensure institutional authorization documentation |

### Institutional Requirements

If conducting this research under an academic or corporate institution:

1. Obtain written approval from your security research ethics board
2. Maintain a lab access log (who accessed what hardware, when)
3. Keep all test machines physically secured (locked lab)
4. Document all firmware modifications in an append-only audit log
5. Follow your institution's responsible disclosure policy for any vulnerabilities discovered

### References

- See [`SECURITY.md`](../SECURITY.md) for vulnerability disclosure procedures
- See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for code contribution guidelines
- See [`docs/TESTING.md`](TESTING.md) for the virtualization-first testing approach (recommended before hardware testing)
