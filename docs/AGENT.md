# Barzakh: Real-Time Monitoring Agent

> **Last Updated:** 2026-10-13 | **Applies to:** `barzakh-agent`

---

## 🛰️ Overview

`barzakh-agent` turns Barzakh from a batch scanner into a continuous monitoring tool. It polls a set of firmware files, rescans whenever a target's mtime changes, records history to SQLite, and forwards findings to a SIEM (Elastic ECS, ArcSight CEF, or QRadar LEEF) and/or a webhook.

```
┌────────────────────────────── agent.toml ──────────────────────────────┐
│  interval_secs = 300                                                   │
└────────────────────────────────┬───────────────────────────────────────┘
                                 │
                    ┌────────────▼────────────┐   mtime change?   ┌──────────────┐
                    │      barzakh-agent      │──────────────────▶│  rescan with │
                    │  (run | once)           │                   │ 132 detectors│
                    └──┬──────────┬───────────┘                   └──────┬───────┘
                       │          │                                      │
          ┌────────────▼───┐  ┌───▼─────────────┐          ┌────────────▼───────┐
          │ barzakh-history│  │ SIEM export      │          │ webhook POST       │
          │ .sqlite (DB)  │  │ ecs | cef | leef │          │ (JSON findings)    │
          └────────────────┘  └───┬─────────────┘          └────────────────────┘
                                  │
                     ┌────────────▼────────────┐
                     │  Elastic / ArcSight /   │
                     │  QRadar                 │
                     └─────────────────────────┘
```

Back to [README](../README.md) · See also [DASHBOARD.md](DASHBOARD.md).

---

## ⚙️ Configuration (`agent.toml`)

```toml
interval_secs = 300
siem_format = "ecs"        # ecs | cef | leef
output = "-"               # stdout or file path
webhook = "https://siem.example.com/hook"   # optional
db = "barzakh-history.sqlite"
[targets]
paths = ["/boot/efi/firmware.bin", "/srv/firmware/router.bin"]
```

| Key | Values | Purpose |
|-----|--------|---------|
| `interval_secs` | integer | Poll interval for target mtimes (default 300) |
| `siem_format` | `ecs` \| `cef` \| `leef` | Export format for findings events |
| `output` | `-` or file path | Where formatted events are written (`-` = stdout) |
| `webhook` | URL (optional) | Findings are additionally POSTed as JSON to this endpoint |
| `db` | file path | SQLite history DB recording every scan and finding |
| `targets.paths` | array | Firmware images to watch |

---

## 🚀 Running

```bash
# Continuous monitoring (default subcommand)
barzakh-agent --config agent.toml run

# run is the default subcommand — this is equivalent
barzakh-agent --config agent.toml

# Single pass: scan all targets once, export events, exit
barzakh-agent --config agent.toml once
```

**Change detection:** the agent polls target mtimes every `interval_secs`. A changed mtime triggers a rescan; unchanged targets are skipped. `once` performs exactly one pass regardless of changes.

---

## 📤 SIEM Export Formats

### Elastic ECS (JSON events)

```json
{
  "@timestamp": "2026-10-13T09:15:02Z",
  "event": {"kind": "alert", "category": ["malware"], "severity": 8},
  "file": {"path": "/boot/efi/firmware.bin", "hash": {"sha256": "9f2c..."}},
  "rule": {"name": "blacklotus", "description": "BlackLotus-style secure boot bypass artifact"},
  "message": "barzakh: critical finding blacklotus on /boot/efi/firmware.bin"
}
```

### ArcSight CEF (single lines)

```text
CEF:0|Barzakh|barzakh-agent|0.5.0|blacklotus|BlackLotus-style secure boot bypass artifact|10|cs1=/boot/efi/firmware.bin cs1Label=targetFile filePath=/boot/efi/firmware.bin fileHash=9f2c... rt=1760349302000
```

### QRadar LEEF (single lines)

```text
LEEF:2.0|Barzakh|barzakh-agent|0.5.0|blacklotus|sev=Critical|filePath=/boot/efi/firmware.bin|fileHash=9f2c...|usrName=barzakh-agent
```

All events are also appended to the history DB, so no alert is lost if the SIEM transport fails.

---

## 🪝 Webhook Delivery

When `webhook` is set, each event is additionally delivered as an HTTP POST:

```bash
# Receive side (example)
curl -s -X POST https://siem.example.com/hook \
  -H "Content-Type: application/json" \
  -d '{"target": "/boot/efi/firmware.bin", "severity": "critical", "detector": "blacklotus", "description": "...", "scan_id": 41}'
```

Delivery is best-effort with retry; failures are logged and never block the monitoring loop.

---

## 🗄️ History Database

`db = "barzakh-history.sqlite"` records:

| Data | Purpose |
|------|---------|
| Scan results per target per run | Trend analysis, drift detection |
| Every finding (detector, severity, offset) | Retrospective incident investigation |
| mtime + SHA-256 per observed revision | Correlate firmware updates with new findings |

Point the [dashboard](DASHBOARD.md) at scheduled scans, or the agent at the same targets, to keep both views consistent.

---

## 📦 systemd Deployment

A hardened unit ships in [packaging/systemd/barzakh-agent.service](../packaging/systemd/barzakh-agent.service):

```bash
# Install
sudo install -Dm 0644 packaging/systemd/barzakh-agent.service /etc/systemd/system/
sudo mkdir -p /etc/barzakh
sudo cp agent.toml /etc/barzakh/agent.toml

# Enable & start
sudo systemctl daemon-reload
sudo systemctl enable --now barzakh-agent
sudo systemctl status barzakh-agent
```

The unit runs the agent as a dynamic unprivileged user with `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, `WatchSecure`-style protections (kernel tunables/modules/logs, control groups, clock, hostname), and a dedicated `StateDirectory` for the history DB.

---

## 📚 Related

- [DASHBOARD.md](DASHBOARD.md) — server dashboard and REST API
- [KNOWLEDGE_BASE.md](KNOWLEDGE_BASE.md) — firmware profiles
- [docker-compose.yml](../docker-compose.yml) — server deployment
- [README](../README.md) — project overview
