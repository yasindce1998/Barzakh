# Barzakh: Web Dashboard & REST API

> **Last Updated:** 2026-10-13 | **Applies to:** `barzakh-server` (dashboard/API binary)

---

## 🖥️ Overview

`barzakh-server` embeds a web dashboard and a JSON REST API for submitting scans, browsing findings, tracking risk-score trends, and managing the firmware knowledge base. State (scans, findings, KB profiles, schedules) persists in a SQLite database.

```bash
# Build & run
cd src/barzakh-scanner-rs
cargo build --release
./target/release/barzakh-server --port 8420 --db barzakh.db

# Or via Docker (see docker-compose.yml / Dockerfile.runtime)
docker compose up -d
```

The dashboard is then available at `http://localhost:8420/`.

```
┌─────────────┐   POST /api/scans    ┌──────────────────┐   scan    ┌─────────────────┐
│   Browser   │─────────────────────▶│  barzakh-server  │──────────▶│ barzakh-scanner │
│  (dashboard)│◀─────────────────────│  (port 8420)     │◀──────────│  (detectors)    │
└─────────────┘  JSON / HTML / SARIF └────────┬─────────┘  findings └─────────────────┘
                                                │
                                        SQLite (barzakh.db)
                                        scans · findings · KB · schedules
```

| Component | Purpose |
|-----------|---------|
| Dashboard UI (`GET /`) | Scan submission, findings browser with severity filtering, risk scores, trends, knowledge-base search |
| REST API (`/api/*`) | Everything the UI does, scriptable — for SOCs, CI, and integrations |
| SQLite DB (`--db`) | Scan history, findings, KB profiles, scheduled scans |

Back to [README](../README.md) · See also [AGENT.md](AGENT.md) (real-time monitoring), [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) (KB CLI).

---

## 🔌 REST API Reference

All endpoints return JSON unless a `format` query parameter selects another rendering. Errors use `{"error": "..."}` with an appropriate HTTP status.

### Health

```bash
curl -s http://localhost:8420/api/health
```

```json
{"status": "ok", "version": "0.5.0", "scans": 42}
```

### List detectors

```bash
curl -s http://localhost:8420/api/detectors
```

```json
{"count": 132, "detectors": [{"name": "blacklotus", "category": "secureboot", "severity": "critical"}, ...]}
```

### Submit a scan

```bash
curl -s -X POST http://localhost:8420/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "/srv/firmware/fw.bin"}'
```

```json
{"scan_id": 7, "status": "complete", "risk_score": 87, "bootkit_detected": true}
```

The scan runs synchronously (firmware images typically scan in well under a second) and the response already carries the verdict summary. Use `GET /api/scans/{id}` for the full findings list.

### List scans

```bash
curl -s http://localhost:8420/api/scans
```

```json
{"scans": [{"scan_id": 7, "target": "/srv/firmware/fw.bin", "status": "complete",
            "bootkit_detected": true, "risk_score": 87, "risk_level": "high",
            "critical": 1, "high": 3, "medium": 6, "low": 11, "info": 4,
            "total_findings": 25, "timestamp": "2026-10-13T09:15:02Z"}]}
```

### Get a single scan

```bash
curl -s http://localhost:8420/api/scans/7
```

```json
{"scan_id": 7, "target": "/srv/firmware/fw.bin", "status": "complete", "bootkit_detected": true,
 "risk_score": 87, "risk_level": "high", "total_findings": 25,
 "summary": {"critical": 1, "high": 3, "medium": 6, "low": 11, "info": 4},
 "timestamp": "2026-10-13T09:15:02Z",
 "findings": [{"detector": "blacklotus", "severity": "critical", "confidence": 0.9,
               "title": "BlackLotus secure boot bypass artifact",
               "description": "UEFI bootkit artifact matching the BlackLotus kill-switch pattern"}]}
```

### Get a scan report (any format)

```bash
# JSON (default)
curl -s "http://localhost:8420/api/scans/7/report?format=json" -o report.json

# HTML — analyst-friendly report
curl -s "http://localhost:8420/api/scans/7/report?format=html" -o report.html

# Markdown
curl -s "http://localhost:8420/api/scans/7/report?format=markdown" -o report.md

# SARIF 2.1.0 — for GitHub code scanning / SIEM ingestion
curl -s "http://localhost:8420/api/scans/7/report?format=sarif" -o barzakh.sarif

# CSV — for spreadsheets and ticket import
curl -s "http://localhost:8420/api/scans/7/report?format=csv" -o report.csv
```

Supported values of `format`: `json`, `html`, `markdown`, `sarif`, `csv`.

### Diff two scans

```bash
curl -s "http://localhost:8420/api/scans/diff?a=6&b=7"
```

```json
{"a": 6, "b": 7, "new_findings": [{"detector": "blacklotus", "severity": "critical"}],
 "resolved_findings": [], "risk_score_delta": +62}
```

Useful for before/after firmware update comparisons (see [baseline workflow](#baseline-workflow)).

### Trends

```bash
curl -s http://localhost:8420/api/trends
```

```json
{"trend": [{"date": "2026-10-01", "avg_risk_score": 12.0, "scans": 3,
            "total_findings": 34, "critical_findings": 2},
           {"date": "2026-10-02", "avg_risk_score": 15.0, "scans": 5,
            "total_findings": 51, "critical_findings": 4}],
 "top_detectors": [{"detector": "entropy_anomaly", "hits": 34},
                   {"detector": "blacklotus", "hits": 12}]}
```

### Knowledge base

```bash
# List profiles
curl -s http://localhost:8420/api/kb

# Add a profile
curl -s -X POST http://localhost:8420/api/kb \
  -H "Content-Type: application/json" \
  -d '{"target": "/srv/firmware/fw.bin", "vendor": "ASUS",
       "device": "PRIME Z690-A", "notes": "golden baseline image"}'
```

See [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) for the full KB data model.

### Adversary payload generation

```bash
curl -s -X POST http://localhost:8420/api/adversary/generate \
  -H "Content-Type: application/json" \
  -d '{"payload": "trampoline", "arch": "x86_64", "size": 65536}'
```

```json
{"payload": "trampoline", "arch": "x86_64", "size": 65536,
 "sha256": "9f2c...", "path": "payloads/trampoline-x86_64-65536.bin"}
```

The payload image is written to the server's payloads directory (`payloads/` by default; override with `--payloads-dir`). The `arch` values are `x86_64`, `aarch64`, `riscv64`, `power64`, and `armv7`.

### Scenarios

```bash
curl -s http://localhost:8420/api/scenarios
```

```json
{"scenarios": [{"name": "smm-persistence-chain",
                "description": "DXE foothold → SMM persistence → runtime hook",
                "stages": 3, "mitre": ["T1542.001", "T1542.003"]}]}
```

See [SCENARIOS.md](SCENARIOS.md) for scenario definitions and the detection-chain report.

### Scheduled scans

```bash
curl -s -X POST http://localhost:8420/api/schedule \
  -H "Content-Type: application/json" \
  -d '{"target": "/srv/firmware/fw.bin", "interval_secs": 3600}'
```

```json
{"status": "scheduled", "schedule_id": 1, "target": "/srv/firmware/fw.bin", "interval_secs": 3600}
```

### Dashboard

```bash
curl -s http://localhost:8420/ | head
```

`GET /` serves the embedded dashboard (no separate frontend deployment). It provides:

| View | Features |
|------|----------|
| Scan submission | Path/URL input, detector selection |
| Findings browser | Severity filtering (Critical/High/Medium/Low/Info), detector grouping, offsets, MITRE tags |
| Risk scores | Per-scan composite score with historical trend line |
| Trends | Detection frequency and risk over time |
| Knowledge base search | Query profiles by vendor, device, hash, notes |

---

## 🔄 Baseline Workflow

Pair the server with the CLI baseline tooling for drift detection:

```bash
# 1. Capture a golden baseline once (PCRs + memory map included)
./scripts/capture-baseline.sh --target fw.bin --output baseline.json

# 2. Submit subsequent scans via the API
curl -s -X POST http://localhost:8420/api/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "fw-new.bin"}'

# 3. Diff old vs new scan results
curl -s "http://localhost:8420/api/scans/diff?a=6&b=7"
```

---

## 🚀 Deployment

| Method | Command |
|--------|---------|
| Manual | `barzakh-server --port 8420 --db barzakh.db` |
| Docker | `docker compose up -d` (see [docker-compose.yml](../docker-compose.yml)) |
| systemd | `systemctl start barzakh-server` (see [packaging/systemd/barzakh-server.service](../packaging/systemd/barzakh-server.service)) |

The systemd unit runs the server as a dynamic unprivileged user with `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, and `StateDirectory=barzakh`.

---

## 📚 Related

- [AGENT.md](AGENT.md) — real-time monitoring agent that pairs with the server
- [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) — KB data model and collaborative sharing
- [INTEL.md](INTEL.md) — IOC feeds consumed during scans
- [README](../README.md) — project overview
