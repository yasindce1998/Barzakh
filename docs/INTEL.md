# Barzakh: Threat Intelligence

> **Last Updated:** 2026-10-13 | **Applies to:** intel detectors, IOC feeds, YARA-subset rules, MISP/MITRE export

---

## 🎯 Overview

Barzakh consumes external threat intelligence to complement its structural detectors: IOC feeds (known hashes and byte patterns), a YARA-subset rule engine, and export paths to MISP events and MITRE ATT&CK mappings.

```
┌──────────────────┐   ┌───────────────────┐   ┌──────────────────────┐
│  intel-feeds/    │──▶│                   │──▶│ IOC findings         │
│  *.json (IOC)    │   │                   │   │ (hash / hex pattern) │
└──────────────────┘   │                   │   └──────────────────────┘
                       │  barzakh-scanner  │
┌──────────────────┐   │      scan         │   ┌──────────────────────┐
│  intel-rules/    │──▶│                   │──▶│ YARA rule matches    │
│  *.yar (rules)   │   │                   │   │ (string / hex)       │
└──────────────────┘   │                   │   └──────────────────────┘
                       └────────┬──────────┘
                                │
                    ┌───────────▼────────────┐
                    │ intel misp / intel attack
                    │ (MISP event, ATT&CK map)│
                    └────────────────────────┘
```

Back to [README](../README.md).

---

## 📦 IOC Feed Format

A feed is a JSON object with a `name` and an `iocs` array. Each IOC is matched by SHA-256 (whole-image or embedded component) or by hex byte `pattern`:

```json
{
  "name": "barzakh-default",
  "version": 1,
  "iocs": [
    {
      "sha256": "d41d8cd98f00b204e9800998ecf8427e",
      "pattern": "hex:DEADBEEF",
      "family": "LoJax",
      "cve": null,
      "description": "LoJax-style SPI implant marker bytes"
    },
    {
      "sha256": null,
      "pattern": "hex:48 8B 04 25 60 D0 3B 00",
      "family": "BlackLotus",
      "cve": "CVE-2023-24932",
      "description": "BlackLotus boot services table access stub"
    }
  ]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `sha256` | string \| null | Known-malicious hash (image or component) |
| `pattern` | string | Byte pattern, `hex:` prefixed, whitespace-separated nibbles allowed |
| `family` | string | Malware family label (LoJax, BlackLotus, CosmicStrand, ...) |
| `cve` | string \| null | Associated CVE, if any |
| `description` | string | Analyst-facing note shown in reports |

### Bundled Feed

The project ships a starter feed at `intel-feeds/barzakh-default.json` covering the reference adversaries modeled by the platform (BlackLotus, LoJax, MoonBounce, CosmicStrand, MosaicRegressor, and friends). Refresh or extend it with:

```bash
./scripts/intel-update.sh                                  # bundled feed note
./scripts/intel-update.sh --feed https://example.com/feed.json
```

`intel-update.sh` validates every feed is JSON with a `name` and an `iocs` array before installing it into `--dir` (default `./intel-feeds`).

---

## 🧬 YARA-Subset Rules

Barzakh supports a pragmatic subset of YARA rule syntax — no imports, no loops, no external variables. A rule has a name, a `strings:` section, and a `condition:`:

```yara
rule blacklotus_stage1
{
    strings:
        $a = "win: boot project" ascii
        $b = { DE AD BE EF 00 01 02 }
        $c = "UEFI" wide ascii
    condition:
        any of them
}
```

| Element | Supported |
|---------|-----------|
| String literals | `"text"` with optional `ascii` / `wide` modifiers |
| Hex patterns | `{ DE AD BE EF }`, wildcards `??` and jumps `[4-8]` |
| Condition | `any of them`, `all of them`, `$a and $b`, `$a or $b`, `not $a` |
| Not supported | imports, file size/pe modules, loops, private rules, references between rules |

Rules live in `intel-rules/*.yar`. Every rule in the directory is compiled and evaluated during scans that pass `--yara`.

---

## 🔍 Scanning with Intel

```bash
# Scan with an IOC feed and a YARA rule directory
barzakh-scanner scan --ioc-feed feed.json --yara rules/ --target fw.bin

# Multiple feeds
barzakh-scanner scan --ioc-feed intel-feeds/barzakh-default.json \
    --ioc-feed custom-feed.json \
    --yara intel-rules/ \
    --target fw.bin
```

IOC and YARA hits appear as findings with `family`, `cve`, and the matched rule name, using the same severity model as built-in detectors.

---

## 🧰 Intel CLI

### List feeds

```bash
barzakh-scanner intel feeds
```

```text
Feed                    IOCs    Version   Updated
barzakh-default         47      1         2026-10-01
custom-feed             12      3         2026-09-28
```

### MISP event export

Export a scan's findings as a MISP-compatible event JSON for ingestion into a threat-sharing platform:

```bash
barzakh-scanner intel misp --target fw.bin --output event.json
```

```json
{
  "Event": {
    "info": "Barzakh scan: fw.bin",
    "date": "2026-10-13",
    "Attribute": [
      {"category": "Payload installation", "type": "sha256",
       "value": "d41d8cd98f00b204e9800998ecf8427e",
       "comment": "LoJax-style SPI implant marker bytes (family: LoJax)"},
      {"category": "Artifacts dropped", "type": "pattern-in-file",
       "value": "hex:DEADBEEF", "to_ids": false}
    ]
  }
}
```

### MITRE ATT&CK mapping

Map findings to ATT&CK techniques for reporting and detection-coverage tracking:

```bash
barzakh-scanner intel attack --target fw.bin
```

```text
Technique      Name                 Findings
T1542.001      System Firmware      blacklotus, fv_tamper
T1542.003      Bootkit              boot_services_hook, trampoline
T1195.002      Component Firmware  me_region_overlap
```

Common mappings produced by the platform:

| Technique | Name | Typical detectors |
|-----------|------|-------------------|
| T1542.001 | System Firmware | `blacklotus`, `fv_tamper`, SPI region detectors |
| T1542.003 | Bootkit | `boot_services_hook`, `trampoline`, signature detectors |
| T1195.002 | Component Firmware | ME/PSP region and component-integrity detectors |

---

## 🔄 Operational Loop

1. **Collect** — `scripts/intel-update.sh` pulls and validates feeds into `intel-feeds/`
2. **Scan** — `barzakh-scanner scan --ioc-feed ... --yara ... --target fw.bin`
3. **Share** — `barzakh-scanner intel misp --output event.json` for your ISAC/MISP community
4. **Report** — `barzakh-scanner intel attack --target fw.bin` for ATT&CK coverage matrices
5. **Tune** — confirm hits via `--report` and the knowledge base ([KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md)); false positives get feed annotations or rule refinement

## 📚 Related

- [scripts/intel-update.sh](../scripts/intel-update.sh) — feed fetcher/validator
- [DASHBOARD.md](DASHBOARD.md) — scan results via REST API
- [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) — firmware profiles
- [README](../README.md) — project overview
