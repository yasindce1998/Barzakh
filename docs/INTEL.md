# Barzakh: Threat Intelligence

> **Last Updated:** 2026-10-14 | **Applies to:** intel detectors, IOC feeds, STIX 2.1 ingestion, YARA-subset rules, MISP/MITRE export

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

### STIX 2.1 ingestion

Public and government feeds (CISA, MISP exports, TAXII collections)
publish **STIX 2.1 bundles**. Barzakh converts the firmware-relevant
indicators directly into its native IOC feed format:

```bash
# Convert a bundle (file or URL) into intel-feeds/:
./scripts/intel-update.sh --stix https://example.com/stix-bundle.json

# Or standalone via the CLI:
barzakh-scanner intel stix --input bundle.json --output feed.json --name csa
# ▶ IOC feed written to feed.json — 12 IOCs from 12 indicators
#   (12 clauses converted, 3 skipped, 9 family attributions)
```

Converted feeds are consumed exactly like native ones:
`barzakh-scanner scan --target fw.bin --ioc-feed feed.json`.

Supported pattern clauses:

| STIX pattern | Becomes |
|--------------|---------|
| `[file:hashes.'SHA-256' = '<hex>']` | SHA-256 hash IOC |
| `[file:name = '<name>']` | ASCII string-pattern IOC |
| other paths / hash types | counted and skipped |

Family attribution follows `relationship_type: "indicates"` edges from
indicators to `malware` objects, so findings read *"Threat-intel match:
LoJax"* rather than an anonymous family. Unsupported clauses (MD5/SHA-1
hashes, process or network indicators) are reported in the conversion
summary — nothing fails silently. `intel-update.sh --stix` locates the
scanner binary via `--scanner`, `$BARZAKH_SCANNER`, the local build
tree, or `PATH`.

---

## 🧬 YARA-Subset Rules

Barzakh supports a pragmatic subset of YARA rule syntax — no loops, no references between rules. A rule has a name, a `strings:` section, and a `condition:`:

```yara
import "pe"

rule blacklotus_stage2 : bootkit uefi
{
    meta:
        family = "BlackLotus"
        cve = "CVE-2022-21894"
    strings:
        $a = "win: boot project" ascii wide
        $b = { DE AD BE EF 00 01 02 }
        $c = /Windows\\System32\\[a-z_]{3,20}\.sys/ nocase
    condition:
        filesize < 500KB and
        2 of them and
        pe.is_pe and
        pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION
}
```

| Element | Supported |
|---------|-----------|
| Text strings | `"text"` with `ascii` / `wide` / `nocase` / `fullword` modifiers |
| Hex patterns | `{ DE AD BE EF }`, wildcards `??` and jumps `[4-8]` (multi-line bodies allowed) |
| Regex strings | `/pattern/` with `ascii` / `wide` / `nocase` |
| Conditions | full boolean expressions: `and` / `or` / `not`, parentheses, comparisons (`== != < > <= >=`), string operators (`contains`, `startswith`, `endswith`, `matches /regex/`), integer arithmetic and bitwise operators |
| Quantifiers | `any of them`, `all of them`, `N of them`, `N% of them`, and set forms `2 of ($a, $b)` / `2 of ($a*)` |
| Occurrence counts | `#a >= 3` |
| File size | `filesize` with `KB` / `MB` suffixes |
| `pe` module subset | `is_pe`, `machine`, `subsystem`, `number_of_sections`, `timestamp`, `entry_point`, `characteristics`, `sections[n].name`, plus `MACHINE_*` / `SUBSYSTEM_*` / `DLL` / `EXECUTABLE_IMAGE` constants |
| External variables | referenced by name, supplied via `--define` (see below); the scanned file's name is available as `filename` |
| Rule syntax niceties | `meta` (family/cve/description kept, others tolerated), tags (`rule X : tag1 tag2`), `private`/`global` prefixes, `import` lines, `//` and `/* */` comments, multi-line sections |
| Not supported | loops (`for … of`), references between rules, other modules (`elf`, `math`, …) |

Rules live in `intel-rules/*.yar`. Every rule in the directory is compiled and evaluated during scans that pass `--yara`. A curated pack of real-world-style firmware threat rules (LoJax, BlackLotus, MoonBounce, ESPectre, Bootkitty, plus deployment-gated rules) lives in `intel-rules/packs/realworld-firmware.yar`; it is not auto-loaded with the directory — pass it explicitly.

### External variables

Rules can reference caller-supplied values — e.g. `revoked == true` or `filename matches /shimx64-[0-9]+\.efi/`. Pass them with `--define` (typed automatically: `true`/`false` → bool, numeric → int, anything else → string). An external that is not defined evaluates to false, so a rule gated on it stays quiet rather than erroring:

```bash
barzakh-scanner scan --target fw.bin \
    --yara intel-rules/packs/realworld-firmware.yar \
    --define revoked=true \
    --define site=berlin-1
```

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
