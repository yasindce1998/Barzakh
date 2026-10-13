# Barzakh: Firmware Knowledge Base

> **Last Updated:** 2026-10-13 | **Applies to:** `barzakh-scanner kb`

---

## 📚 Overview

The knowledge base (KB) is a SQLite-backed catalog of firmware profiles: every image you have scanned, what hardware it came from, and what you learned about it. Profiles anchor baselines, tune detectors per platform, and enable **privacy-preserving cross-team sharing** of firmware knowledge.

| Capability | CLI |
|------------|-----|
| Record a profile | `kb add` |
| Browse profiles | `kb list` |
| Find profiles | `kb search --query <term>` |
| Export for sharing | `kb export --output profiles.json` |
| Import shared profiles | `kb import --input profiles.json [--anonymize]` |

Back to [README](../README.md).

---

## 🧩 CLI

### Add a profile

```bash
barzakh-scanner kb add --target fw.bin --vendor ASUS --device "PRIME Z690-A" --notes "golden baseline image"
```

The scanner computes the hash and structural facts itself — you supply the provenance:

```text
Profile recorded:
  sha256:     9f2c8e41d0...a7
  size:       16777216
  vendor:     ASUS
  device:     PRIME Z690-A
  arch:       x86_64
  created:    2026-10-13T09:15:02Z
```

### List profiles

```bash
barzakh-scanner kb list
```

```text
SHA256 (first 12)   Vendor   Device              Arch    Version   Created
9f2c8e41d0a7        ASUS     PRIME Z690-A        x86_64  3607      2026-10-13
4b1d0093ff21        ASUS     ROG STRIX B550-F    x86_64  2809      2026-10-09
c7e2a5b80944        Supermicro X12SPI-TF         x86_64  3.1       2026-10-02
```

### Search

```bash
barzakh-scanner kb search --query "PRIME"
barzakh-scanner kb search --query "9f2c8e41d0a7"
```

Search matches vendor, device, family, version, notes, and hash prefixes.

### Export / Import

```bash
# Export (optionally anonymized) for sharing with another team
barzakh-scanner kb export --output profiles.json
barzakh-scanner kb export --output profiles.json --anonymize

# Import shared profiles
barzakh-scanner kb import --input profiles.json
```

---

## 🗂️ Profile Schema

Each profile persists in SQLite:

| Field | Type | Example |
|-------|------|---------|
| `sha256` | hash | `9f2c8e41d0...a7` |
| `size` | bytes | `16777216` |
| `vendor` | string | `ASUS` |
| `device` | string | `PRIME Z690-A` |
| `family` | string | `Z690` |
| `version` | string | `3607` |
| `arch` | string | `x86_64` |
| `notes` | free text | `"golden baseline image; FLOCKDN set"` |
| `cve` | links | `["CVE-2023-24932"]` |
| `created` | timestamp | `2026-10-13T09:15:02Z` |

---

## 🔒 Anonymized Export

`--anonymize` replaces `vendor` and `device` with SHA-256 prefixes of their values:

```json
{
  "format": "barzakh-kb-profiles",
  "version": 1,
  "anonymized": true,
  "profiles": [
    {
      "sha256": "9f2c8e41d0...a7",
      "size": 16777216,
      "vendor": "sha256:1a2b3c4d5e6f",
      "device": "sha256:9f8e7d6c5b4a",
      "family": null,
      "version": "3607",
      "arch": "x86_64",
      "notes": "golden baseline image; FLOCKDN set",
      "cve": [],
      "created": "2026-10-13T09:15:02Z"
    }
  ]
}
```

This preserves the *technical* value (hash, size, arch, notes, findings context) while removing information that could identify the exact hardware fleet — enabling collaborative sharing where shipping vendor/device names is contractually or operationally sensitive. Consistent hashing means both teams can still correlate profiles of the same vendor/device without learning the plaintext.

---

## 🤝 Collaborative Workflow

The KB is designed for multi-team detection tuning without sharing firmware binaries (which are usually redistribution-restricted):

```
  Team A (lab)                          Team B (SOC)
┌──────────────────┐                  ┌──────────────────┐
│ kb add scans of  │                  │ Receives         │
│ their hardware   │                  │ profiles.json    │
└────────┬─────────┘                  └────────▲─────────┘
         │ kb export --output profiles.json   │
         │ (optional --anonymize)             │
         └────────────────────────────────────┘
                                              │
                                   ┌──────────▼──────────┐
                                   │ kb import --input   │
                                   │ profiles.json       │
                                   └──────────┬──────────┘
                                              │
                                   ┌──────────▼──────────┐
                                   │ Cross-team detector │
                                   │ tuning: which FPs   │
                                   │ recur on which      │
                                   │ platforms?          │
                                   └─────────────────────┘
```

1. **Export** — team A exports profiles (anonymized if required by policy)
2. **Share** — the JSON file travels over any approved channel; no firmware leaves the lab
3. **Import** — team B merges the profiles into their KB
4. **Tune** — both teams see which detectors fire on which platforms; recurring false positives on a shared platform profile become coordinated detector tuning

Pair exports with [intel feeds](INTEL.md) to ship both *what you saw* (IOC feeds) and *where you saw it* (KB profiles).

---

## 🔗 Integrations

| Integration | How |
|-------------|-----|
| [Dashboard](DASHBOARD.md) | `GET /api/kb` and `POST /api/kb` expose the same KB |
| [HIL lab automation](LAB_AUTOMATION.md) | `hil-runner.sh --phase verify` suggests a `kb add` for every scan |
| [Agent](AGENT.md) | Agent history DB and KB together give fleet-wide drift context |
| [Baselines](../scripts/capture-baseline.sh) | Baseline JSON records reference the KB profile of the golden image |

## 📚 Related

- [DASHBOARD.md](DASHBOARD.md) — KB via REST API
- [INTEL.md](INTEL.md) — IOC feeds
- [KNOWLEDGE_BASE.md](#) ← you are here
- [README](../README.md) — project overview
