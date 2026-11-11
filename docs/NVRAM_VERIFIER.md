# NVRAM and measured-boot evidence

`nvram_verifier` correlates authenticated variable entries (`PK`, `KEK`, `db`,
`dbx`) with GUID/name/value measurements in a **separately captured same-boot**
TCG binary event log. The bounded parser supports legacy TCG events and the TPM2
SpecID/crypto-agile format. It uses `EV_EFI_VARIABLE_DRIVER_CONFIG` in PCR7;
authorization events are not interchangeable with policy-state measurements.

```sh
barzakh-scanner scan --target variables.bin --event-log same-boot-tcg.bin --json
```

| Available evidence | Result |
|---|---|
| No supported authenticated policy variables | `not_applicable` |
| Variables but no supplied event log | `insufficient_evidence`; scan is not complete |
| Historical synthetic `$VSS` layout | `insufficient_evidence`; unsupported layout |
| No matching GUID/name measurement | Informational, insufficient-evidence finding |
| Matching GUID/name, differing value bytes | High-severity structural discrepancy; investigate acquisition timing and authorized changes |
| Matching values | No discrepancy found; **not** proof of trusted boot |

The log is parsed once in `ScanContext`. It is **not TPM-quote verified**. A
malicious or stale log can mislead correlation; collect both artifacts from the
same boot and preserve acquisition hashes/provenance. Findings include offsets,
structure paths, expected/observed values, and evidence strength.

Absence of a log inside a firmware image does not establish an unmeasured write.
Likewise, a `dbx` timestamp older than `db` is not proof of rollback: different
variables can legitimately be updated at different times. Neither signal alone
produces the previous Critical/High downgrade claim.

The historical `nvram_silent_downgrade` fixture remains a visible coverage gap;
its regression test now expects inconclusive evidence. It must be replaced or
augmented with independently labeled paired captures before claiming recall.

Before remediation, preserve evidence, compare vendor-approved policy/baselines,
and investigate authorized updates. Do not clear a TPM or re-enroll keys solely
because a heuristic finding appeared: those operations can invalidate sealed
secrets and recovery access.
