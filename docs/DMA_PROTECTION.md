# Barzakh: Pre-Boot DMA Protection

> **Last Updated:** 2026-10-14 | **Applies to:** `dmar_enforcement`, `ivrs_table`, `iommu_dmar` detectors; `dmar_remap_hole`, `dma_window_bypass`, `dmar_neuter` payloads

---

## 🛡️ Overview

Pre-boot DMA attacks exploit the window between platform reset and `ExitBootServices` during which the IOMMU (Intel VT-d / AMD-Vi) is described by firmware ACPI tables but not yet enforced by the OS. An attacker with physical access — or a malicious peripheral, or a Thunderbolt/USB4 attack tool like Thunderspy/PCILeech — can read and write host memory in this window, including the DXE driver region that later verifies Secure Boot.

Barzakh's DMA protection coverage answers one question: **does the platform's IOMMU description actually protect memory before the OS takes over?**

```
 platform reset
      │
      ▼
 ┌─────────────┐   DMAR/IVRS ACPI tables describe    ┌──────────────────────┐
 │  PEI / DXE  │   translation hardware + reserved   │  DMA window OPEN     │
 │  (firmware) │ ──────────────────────────────────▶ │  (no enforcement!)   │
 └─────────────┘                                      └──────────┬───────────┘
      │                                                          │ device DMA
      │                                                          │ can reach
      ▼                                                          ▼
 ExitBootServices ──── OS programs VT-d / AMD-Vi ──── DMA window CLOSED
```

## Detectors

### `iommu_dmar` — neutered tables

Fires on `DMAR`/`IVRS` tables whose declared length enumerates **zero** remapping units (DRHD/IVHD): the OS believes the platform has no IOMMU at all and never programs translation. This is the simplest tamper — a single length field.

### `dmar_enforcement` — remap holes (Intel)

Walks a *populated* DMAR's remapping structures and flags:

| Signal | Severity | Meaning |
|---|---|---|
| RMRR span > 16 MiB | Critical | A "reserved memory region" that covers effectively all of RAM — a unity mapping that aliases host memory into device-addressable space despite VT-d being enabled (CVE-2025-11901 / CVE-2025-14302 class) |
| Entry length overruns table | High | Forged entry walk — the table cannot be parsed as published |
| RMRRs present, zero DRHDs | High | Self-contradictory table: reserved regions with no translation hardware to enforce them |

Legitimate RMRRs cover small legacy compatibility buffers (USB/EGA/VGA), typically well under 16 MiB.

### `ivrs_table` — remap holes (AMD)

The AMD-Vi counterpart: walks IVHD/IVMD blocks and flags IVMD blocks mapping > 16 MiB (the AMD form of the full-memory remap hole), forged block walks, and memory blocks with zero IVHD units.

## Payloads (adversarial validation)

| Payload | Models |
|---|---|
| `dmar_neuter` | DMAR truncated to its 48-byte prologue — zero DRHD units |
| `dmar_remap_hole` | Well-formed DMAR with INTR_REMAP set and a single RMRR reserving `0x0–0xFFFFFFFFFFFF` |
| `dma_window_bypass` | The exploitation side: remap-hole DMAR **plus** a forged PCI option ROM header whose BAR points at the DXE driver region — a PCILeech-style device write before `ExitBootServices` |

The `dma-preboot-chain` scenario composes all three stages into a full kill chain (neuter → remap window → DXE overwrite → boot hook).

## Hardening guidance

1. Verify the OS enables kernel DMA protection: `intel_iommu=on` (or `DMAR_DEFAULT_ON`), `amd_iommu=on`.
2. Compare DMAR/IVRS tables against a golden baseline from vendor firmware.
3. Enable `BootTimeDmar` / kernel lockdown; on Linux, check `/sys/class/iommu` population and `dmesg | grep -e DMAR -e AMD-Vi`.
4. For Thunderbolt/USB4 exposed machines, enable BIOS "DMA protection" / Kernel DMA Protection (KDMAP) via `DEFER` policy.
