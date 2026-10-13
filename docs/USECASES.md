# Barzakh: Offense & Defense Use Cases

This document describes the operational use cases for Project Barzakh across both offensive (red-team) and defensive (blue-team) scenarios. All use cases operate within the project's ethical constraints: air-gapped environments, virtualization only, and institutional oversight.

## Offense Use Cases (Red Team)

### UC-O1: Bootkit TTP Emulation for Detection Gap Analysis

**Scenario:** A security research team needs to understand whether their firmware monitoring stack can detect real-world bootkit techniques (BlackLotus, CosmicStrand, LoJax).

**How Barzakh helps:**
1. Build BootkitPkg DXE drivers with EDK2 (simulation mode by default)
2. Deploy into QEMU with OVMF firmware
3. The implants model each TTP: Boot Services hooking, ExitBootServices interception, MSR manipulation, exception vector relocation
4. Extract memory dumps post-boot
5. Feed to the target detection tool and measure what it catches vs. misses

**Artifacts produced:**
- Infected firmware images with known-malicious DXE drivers loaded
- Memory dumps showing hooked function pointers, trampolines, and relocated vectors
- Ground truth logs (serial output) documenting exactly what was modified

**Key insight:** Unlike static samples from malware zoos, Barzakh produces *live* bootkit behavior in a controlled VM — the implants actually hook tables and redirect execution, creating realistic runtime artifacts.

---

### UC-O2: Automated Payload Generation for Scanner Stress-Testing

**Scenario:** A detection engine claims to find firmware threats. How do you verify that claim systematically?

**How Barzakh helps:**
1. The `barzakh-adversary` crate generates binary payloads targeting 5 distinct detection categories
2. Each payload is crafted to trigger specific detector logic (not just pattern-matching, but structural analysis like CRC validation and pointer range checks)
3. The corpus generator produces malicious + clean pairs for automated TPR/FPR measurement
4. Run against any scanner (not just Barzakh's own) to benchmark detection rates

**Example workflow (using standalone binary):**
```bash
# List all available payloads
barzakh-adversary list

# Generate a test corpus
barzakh-adversary corpus --output ./corpus

# Validate detection rates against the corpus
barzakh-adversary validate --corpus ./corpus
```

**Alternative workflow (via cargo tests):**
```bash
# Run corpus validation through the test harness
cargo test -p barzakh-adversary -- --ignored corpus_validation

# The corpus includes:
#   malicious_trampoline_x86_64.bin  — JMP trampoline in runtime memory
#   malicious_boot_services_hook.bin — BST with hooked pointers + bad CRC
#   malicious_pe_inject.bin          — PE/COFF at page-aligned offset
#   malicious_fv_tamper.bin          — FV header with corrupted checksum
#   malicious_signature_plant.bin    — Known bootkit byte signatures
#   clean_*.bin                      — Corresponding benign reference files
```

**Key insight:** The payloads are architecture-aware (x86_64 + ARM64), structurally valid (not just random bytes with signatures appended), and exercise the *logic* of detectors — not just their pattern databases.

---

### UC-O3: Functional Firmware Implant Development (QEMU EL1)

**Scenario:** A researcher needs to demonstrate that exception vector relocation is a viable persistence mechanism on AArch64, and wants to study the exact memory layout produced.

**How Barzakh helps:**
1. Build ExceptionVectorHook with `-DBARZAKH_FUNCTIONAL=1`
2. Boot in QEMU `virt` machine (runs at EL1)
3. The module performs real VBAR_EL1 relocation:
   - Reads current vector table base via `MRS`
   - Allocates page-aligned memory
   - Copies the original 2KB table
   - Patches synchronous exception entry with LDR/BR trampoline
   - Redirects VBAR_EL1 via `MSR + ISB`
4. Dump memory and observe the modified vector table in place

**Safety:** The trampoline points back to the original handler — the hook is non-destructive. The module only activates with an explicit build flag; default builds remain simulation-only.

---

### UC-O4: Evasion Technique Benchmarking

**Scenario:** How robust is a detector against variants? Can it be evaded by changing offsets, randomizing addresses, or fragmenting the payload?

**How Barzakh helps:**
1. Use `PayloadConfig` to vary parameters (size, architecture, layout)
2. Modify individual payload generators to test edge cases:
   - Move PE headers to non-standard page-aligned offsets
   - Vary trampoline placement within the binary
   - Use near-valid CRC values in BST hooks
   - Fragment firmware volume across multiple regions
3. Run against the scanner to identify detection boundaries

**Key insight:** By programmatically generating payload variants in Rust, researchers can systematically explore the decision boundary of each detector — something impossible with a fixed set of malware samples.

---

### UC-O5: Purple Team Exercise — Attack-Defend Iteration

**Scenario:** A team wants to iteratively improve both attack and defense capabilities.

**How Barzakh helps:**
1. **Red iteration:** Add a new payload type to `barzakh-adversary` that the scanner doesn't currently detect
2. **Blue iteration:** Add or improve a detector in `barzakh-core` to catch the new payload
3. **Validate:** Run `cargo test -p barzakh-adversary` — the new payload's `expected_detections()` now passes
4. **Repeat:** Each cycle tightens both sides

The project's CI enforces this loop: if a payload's expected detection regresses, the pipeline fails.

---

## Defense Use Cases (Blue Team)

### UC-D1: Firmware Integrity Monitoring in Production

**Scenario:** A SOC team needs to periodically scan firmware dumps from production servers to detect unauthorized modifications.

**How Barzakh helps:**
1. Use `barzakh-scanner` CLI to scan extracted firmware images
2. Compare against a known-good baseline (`--baseline baseline.json`)
3. Generate HTML/JSON reports for analyst review
4. Alert on findings with severity >= High

**Example workflow:**
```bash
# Establish baseline from golden image
barzakh-scanner baseline --target golden-firmware.bin --output baseline.json

# Periodic scan against baseline
barzakh-scanner scan --target current-firmware.bin --baseline baseline.json

# Generate report for analyst review
barzakh-scanner report --target current-firmware.bin --format html --output report.html
```

**Detection coverage:** Boot Services table integrity, firmware volume checksums, PE injection in runtime memory, known bootkit signatures, trampoline patterns, entropy anomalies, Android boot chain attacks (pKVM, DICE, GKI, RKP, Trusty, bootctrl, vendor_dlkm, bootconfig, binary transparency), Apple/iOS boot chain (Img4, Trust Cache, AMFI, KTRR, SEP), wireless firmware (WLAN/Bluetooth), telecom baseband (5G RAN, VoLTE, IMS, O-RAN, SIM Toolkit, small cell), satellite systems (CCSDS, GNSS, VSAT, Starlink/LEO terminals, transponders, ground stations), and multi-arch heuristics — 132 detectors total.

---

### UC-D2: Measured Boot Attestation Validation

**Scenario:** A fleet management system collects TPM PCR values from endpoints. How do you verify those measurements are trustworthy?

**How Barzakh helps:**
1. The PCR Analysis detector compares reported PCR values against expected measurements
2. The PCR Replay detector reconstructs expected PCR values from the event log and flags mismatches (detects replayed/forged attestations)
3. The PCR Oracle applies statistical analysis to detect subtle drift across a fleet

**What it catches:**
- Bootkits that hook `EFI_TCG2_PROTOCOL` to replay clean PCR values
- Modified boot sequences that don't match the event log
- Firmware updates that silently alter boot measurements

---

### UC-D3: Incident Response — Memory Dump Triage

**Scenario:** During an incident, a responder has extracted a physical memory dump from a suspected compromised UEFI system. They need to quickly determine if firmware-level persistence is present.

**How Barzakh helps:**
1. Point the scanner at the raw memory dump
2. The 132 detectors run in parallel (< 500ms for typical dumps)
3. Findings are prioritized by severity (Critical > High > Medium > Low > Info)
4. The HTML report provides analyst-friendly descriptions of each finding

**Triage decision tree:**
- Critical findings (e.g., Boot Services CRC mismatch + suspicious pointers) → confirm active bootkit
- High findings (e.g., PE in runtime memory, FV checksum failure) → likely compromise, investigate further
- Medium/Low (e.g., entropy anomalies, single signature match) → possible false positive, correlate with other evidence

---

### UC-D4: CI/CD Gating for Firmware Build Pipelines

**Scenario:** An OEM builds custom UEFI firmware and needs automated security checks before releasing updates.

**How Barzakh helps:**
1. Integrate `barzakh-scanner` as a CI gate in the firmware build pipeline
2. Scan every firmware image before release
3. Fail the build on any High/Critical finding
4. Track detection metrics over time to catch regressions

**CI integration pattern:**
```yaml
firmware-security-check:
  runs-on: ubuntu-latest
  steps:
    - name: Scan firmware image
      run: |
        barzakh-scanner scan --target build/firmware.bin
        barzakh-scanner report --target build/firmware.bin --format json --output scan.json
        # Fail if any critical/high findings
        jq -e '.summary.critical == 0 and .summary.high == 0' scan.json
```

---

### UC-D5: Detection Rule Development and Validation

**Scenario:** A detection engineer wants to write a new rule for a novel firmware threat and needs ground-truth test data.

**How Barzakh helps:**
1. Write a new `Payload` implementation in `barzakh-adversary` that generates the artifact the rule should catch
2. Implement the detector in `barzakh-core`
3. The adversary's `expected_detections()` declares the detector name and minimum severity
4. Integration tests automatically verify the rule fires correctly
5. Corpus validation ensures no false positives on clean samples

**Development loop:**
```bash
# 1. Write payload + detector
# 2. Run tests
cargo test -p barzakh-adversary
# 3. Verify no FP regression
cargo test -p barzakh-adversary -- --ignored corpus_validation
# 4. Check all existing detectors still pass
cargo test --workspace
```

---

### UC-D6: Security Training and Education

**Scenario:** A university course on firmware security needs hands-on lab exercises where students can observe bootkit behavior safely.

**How Barzakh helps:**
1. Students build BootkitPkg in simulation mode (default) — no risk of escape
2. Serial output shows exactly what each module does: "Hooking gBS->AllocatePool at address X", "Relocating VBAR_EL1 to Y"
3. Students then use `barzakh-scanner` to analyze the resulting artifacts
4. They can add their own payloads to `barzakh-adversary` and test if the scanner catches them
5. The project's safety mechanisms (UUID binding, time-bomb, air-gap) serve as teaching examples of responsible research practices

**Lab progression:**
1. Observe simulation logs → understand bootkit mechanics
2. Scan infected dumps → learn detection heuristics
3. Write a new payload → practice adversarial thinking
4. Improve a detector → practice defensive engineering

---

## Combined Scenarios

### UC-C1: Full-Stack Validation (End-to-End)

The complete Barzakh pipeline exercises both offense and defense:

```
┌──────────────┐     ┌───────────────┐     ┌──────────────┐     ┌──────────────┐
│  C Implants  │────▶│  QEMU Boot    │────▶│ Memory Dump  │────▶│   Scanner    │
│  (BootkitPkg)│     │  (OVMF+vTPM)  │     │  Extraction  │     │  (barzakh)   │
└──────────────┘     └───────────────┘     └──────────────┘     └──────────────┘
                                                                        │
┌──────────────┐                                                        ▼
│  Adversary   │──── generates payloads ────────────────────────▶ validates detection
│  (Rust)      │                                                  reports TPR/FPR
└──────────────┘
```

**CI enforces both paths:**
- `qemu-e2e` job: builds implants, boots QEMU, dumps memory, scans
- `adversary-test` job: generates payloads, scans, validates coverage

### UC-C2: Regression Prevention

When any component changes (scanner rules, payload generators, or C implants), the CI pipeline ensures:
1. No detection regression (existing payloads still detected)
2. No false positive increase (clean files remain clean)
3. No build breakage across the full workspace
4. Formatting and lint compliance maintained

This creates a ratchet: detection capabilities can only improve, never silently degrade.
