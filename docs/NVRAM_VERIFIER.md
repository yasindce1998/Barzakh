# Barzakh: NVRAM & Measured Boot Verifier

> **Last Updated:** 2026-10-14 | **Applies to:** `nvram_verifier` detector; `nvram_silent_downgrade` payload

---

## 🔐 Overview

The most dangerous Secure Boot bypasses are the *silent* ones: they change boot policy without leaving a trace in the TPM measurement log. The CVE-2025-3052 / CVE-2024-7344 class achieves this via a **vulnerable signed UEFI binary** (or a custom PE loader) that writes `db`/`dbx` variables directly to NVRAM — the write never passes through a measured code path, so `PCR[7]` stays clean while the boot policy has changed.

`nvram_verifier` cross-checks two independent sources of truth that firmware images carry:

```
┌────────────────────────────┐        ┌─────────────────────────────────┐
│  UEFI variable store $VSS  │        │  TCG event log (TPM2 log)       │
│  - db / dbx / PK / KEK     │        │  - EV_EFI_VARIABLE_DRIVER_AUTH  │
│  - EFI_TIME timestamps     │        │  - EV_EFI_VARIABLE_BOOT         │
│    per variable            │        │  - EV_EFI_VARIABLE_AUTHORITY    │
└─────────────┬──────────────┘        └──────────────┬──────────────────┘
              │            cross-check              │
              └────────────────► ⚡ ◄───────────────┘
                        finding when they disagree
```

## Findings

| Signal | Severity | Meaning |
|---|---|---|
| Secure Boot variables present, zero `EV_EFI_VARIABLE_*` events in the TCG log | Critical | An **unmeasured variable write** — the signature of a silent downgrade via a vulnerable signed binary or custom loader |
| `dbx` timestamp older than `db` timestamp | High | Revocation-list rollback: known-bad certificates remain trusted because dbx predates the current db enrollment |

Both checks require a structurally valid authenticated variable store (`$VSS` signature, `0x55AA` start IDs, plausible name/data sizes) — random buffers do not trigger findings.

## How the walk works

1. Locate `$VSS` store signatures; parse the 28-byte `VARIABLE_STORE_HEADER`.
2. Walk `AUTHENTICATED_VARIABLE_HEADER` entries (60 fixed bytes: StartId, State, Attributes, MonotonicCount, EFI_TIME TimeStamp, PubKeyIndex, NameSize, DataSize, VendorGuid), followed by the 4-byte-aligned UTF-16LE name and payload.
3. Extract names and timestamps of Secure Boot policy variables (`db`, `dbx`, `PK`, `KEK`).
4. Scan the TCG log region of the image for the event types that must accompany measured variable writes.
5. Flag disagreements (missing measurements, timestamp inversions).

## Payload (adversarial validation)

`nvram_silent_downgrade` emits a variable store with `db` enrolled 2026-06 and `dbx` frozen at 2024-01, and **no** TCG events anywhere — exercising both findings at once. The `nvram-downgrade-chain` scenario composes it after a `signed_loader_chain` stage (the CVE-2024-7344 loader that performs the write) and finishes with runtime persistence.

## Hardening guidance

1. Compare variable stores against a golden baseline (`barzakh diff` between dumps).
2. Re-enroll PK/KEK/db from vendor media; re-provision the TPM (clear + re-seal) before trusting attestation again.
3. Audit the TCG event log for `EV_EFI_VARIABLE_DRIVER_AUTH` coverage of every Secure Boot policy change.
4. Apply vendor firmware updates revoking known-vulnerable UEFI binaries from dbx.
