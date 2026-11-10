//! Scan history: record, list, diff and trend scan results in SQLite.

use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use barzakh_core::ScanResult;

/// A stored scan summary row.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRecord {
    pub id: i64,
    pub timestamp: String,
    pub target: String,
    /// Lifecycle: `running` → `complete` | `failed`.
    pub status: String,
    /// Failure message when `status = failed`.
    pub error: Option<String>,
    pub bootkit_detected: bool,
    pub risk_score: u32,
    pub risk_level: String,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
}

/// A finding that appeared or disappeared between two scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffEntry {
    pub status: &'static str,
    pub detector: String,
    pub title: String,
    pub severity: String,
}

/// Trend point: findings per day.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrendPoint {
    pub day: String,
    pub scans: usize,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub mean_risk: f64,
}

/// SQLite-backed scan history store.
pub struct ScanStore {
    conn: Connection,
}

impl ScanStore {
    /// Open (creating if needed) the history database at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = if path == Path::new(":memory:") {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'complete',
                error TEXT,
                bootkit_detected INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                critical_count INTEGER NOT NULL,
                high_count INTEGER NOT NULL,
                medium_count INTEGER NOT NULL,
                low_count INTEGER NOT NULL,
                info_count INTEGER NOT NULL,
                findings_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);
            CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);",
        )?;
        // Migration: databases created before the async-scan API have no
        // status/error columns. Existing rows are finished scans.
        let columns: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(scans)")?;
            let names = stmt.query_map([], |row| row.get::<_, String>(1))?;
            names.collect::<Result<Vec<_>, _>>()?
        };
        if !columns.iter().any(|c| c == "status") {
            conn.execute_batch(
                "ALTER TABLE scans ADD COLUMN status TEXT NOT NULL DEFAULT 'complete';
                 ALTER TABLE scans ADD COLUMN error TEXT;",
            )?;
        }
        Ok(Self { conn })
    }

    /// Record a scan result; returns the scan id.
    pub fn record(&mut self, result: &ScanResult) -> anyhow::Result<i64> {
        self.conn.execute(
            "INSERT INTO scans (ts, target, bootkit_detected, risk_score, risk_level, \
             total_findings, critical_count, high_count, medium_count, low_count, info_count, \
             findings_json) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                result.scan_info.start_time,
                result.scan_info.target,
                result.summary.bootkit_detected as i64,
                result.risk.score,
                result.risk.level.to_string(),
                result.summary.total_findings as i64,
                result.summary.critical_count as i64,
                result.summary.high_count as i64,
                result.summary.medium_count as i64,
                result.summary.low_count as i64,
                result.summary.info_count as i64,
                serde_json::to_string(&result.findings)?,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Insert a placeholder row for a scan that is about to run in the
    /// background (`status = running`); returns the scan id clients can
    /// poll. The row is completed by [`ScanStore::complete`] or
    /// [`ScanStore::fail`].
    pub fn record_pending(&mut self, target: &str) -> anyhow::Result<i64> {
        self.conn.execute(
            "INSERT INTO scans (ts, target, status, bootkit_detected, risk_score, risk_level, \
             total_findings, critical_count, high_count, medium_count, low_count, info_count, \
             findings_json) \
             VALUES (?1, ?2, 'running', 0, 0, 'pending', 0, 0, 0, 0, 0, 0, '[]')",
            rusqlite::params![chrono::Utc::now().to_rfc3339(), target],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Fill in a `running` scan row with its finished result.
    pub fn complete(&mut self, id: i64, result: &ScanResult) -> anyhow::Result<()> {
        let changed = self.conn.execute(
            "UPDATE scans SET status = 'complete', error = NULL, bootkit_detected = ?2, \
             risk_score = ?3, risk_level = ?4, total_findings = ?5, critical_count = ?6, \
             high_count = ?7, medium_count = ?8, low_count = ?9, info_count = ?10, \
             findings_json = ?11 WHERE id = ?1",
            rusqlite::params![
                id,
                result.summary.bootkit_detected as i64,
                result.risk.score,
                result.risk.level.to_string(),
                result.summary.total_findings as i64,
                result.summary.critical_count as i64,
                result.summary.high_count as i64,
                result.summary.medium_count as i64,
                result.summary.low_count as i64,
                result.summary.info_count as i64,
                serde_json::to_string(&result.findings)?,
            ],
        )?;
        if changed == 0 {
            anyhow::bail!("scan {id} not found");
        }
        Ok(())
    }

    /// Mark a `running` scan as failed with an error message.
    pub fn fail(&mut self, id: i64, error: &str) -> anyhow::Result<()> {
        let changed = self.conn.execute(
            "UPDATE scans SET status = 'failed', error = ?2 WHERE id = ?1",
            rusqlite::params![id, error],
        )?;
        if changed == 0 {
            anyhow::bail!("scan {id} not found");
        }
        Ok(())
    }

    /// List the most recent `limit` scans (newest first).
    pub fn list(&self, limit: usize) -> anyhow::Result<Vec<ScanRecord>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, target, status, error, bootkit_detected, risk_score, risk_level, \
             total_findings, critical_count, high_count, medium_count, low_count, info_count \
             FROM scans ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], row_to_record)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Fetch the full findings JSON for one scan.
    pub fn get_findings(&self, id: i64) -> anyhow::Result<Vec<barzakh_core::Finding>> {
        let json: String = self.conn.query_row(
            "SELECT findings_json FROM scans WHERE id = ?1",
            [id],
            |row| row.get(0),
        )?;
        Ok(serde_json::from_str(&json)?)
    }

    /// Fetch the full scan record for one scan.
    pub fn get(&self, id: i64) -> anyhow::Result<ScanRecord> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, target, status, error, bootkit_detected, risk_score, risk_level, \
             total_findings, critical_count, high_count, medium_count, low_count, info_count \
             FROM scans WHERE id = ?1",
        )?;
        let mut rows = stmt.query_map([id], row_to_record)?;
        rows.next()
            .transpose()?
            .ok_or_else(|| anyhow::anyhow!("scan {id} not found"))
    }

    /// Diff two scans by (detector, title) key: what is new, what resolved.
    pub fn diff(&self, older_id: i64, newer_id: i64) -> anyhow::Result<Vec<DiffEntry>> {
        let older = self.get_findings(older_id)?;
        let newer = self.get_findings(newer_id)?;

        let key = |f: &barzakh_core::Finding| (f.detector.clone(), f.title.clone());
        let older_keys: std::collections::HashSet<_> = older.iter().map(key).collect();
        let newer_keys: std::collections::HashSet<_> = newer.iter().map(key).collect();

        let mut out = Vec::new();
        for f in &newer {
            if !older_keys.contains(&(f.detector.clone(), f.title.clone())) {
                out.push(DiffEntry {
                    status: "new",
                    detector: f.detector.clone(),
                    title: f.title.clone(),
                    severity: f.severity.to_string(),
                });
            }
        }
        for f in &older {
            if !newer_keys.contains(&(f.detector.clone(), f.title.clone())) {
                out.push(DiffEntry {
                    status: "resolved",
                    detector: f.detector.clone(),
                    title: f.title.clone(),
                    severity: f.severity.to_string(),
                });
            }
        }
        Ok(out)
    }

    /// Total number of recorded scans.
    pub fn count(&self) -> anyhow::Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Daily trend aggregation.
    pub fn trends(&self) -> anyhow::Result<Vec<TrendPoint>> {
        let mut stmt = self.conn.prepare(
            "SELECT substr(ts, 1, 10) AS day, COUNT(*), SUM(total_findings), \
             SUM(critical_count), AVG(risk_score) FROM scans GROUP BY day ORDER BY day",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TrendPoint {
                day: row.get(0)?,
                scans: row.get::<_, i64>(1)? as usize,
                total_findings: row.get::<_, Option<i64>>(2)?.unwrap_or(0) as usize,
                critical_findings: row.get::<_, Option<i64>>(3)?.unwrap_or(0) as usize,
                mean_risk: row.get::<_, Option<f64>>(4)?.unwrap_or(0.0),
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Most-triggered detectors across all recorded scans, with hit counts.
    pub fn top_detectors(&self, limit: usize) -> anyhow::Result<Vec<(String, usize)>> {
        let mut stmt = self.conn.prepare("SELECT findings_json FROM scans")?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        for row in rows {
            let json = row?;
            let findings: Vec<barzakh_core::Finding> =
                serde_json::from_str(&json).unwrap_or_default();
            for finding in findings {
                *counts.entry(finding.detector).or_default() += 1;
            }
        }
        let mut out: Vec<(String, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out.truncate(limit);
        Ok(out)
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<ScanRecord> {
    Ok(ScanRecord {
        id: row.get(0)?,
        timestamp: row.get(1)?,
        target: row.get(2)?,
        status: row.get(3)?,
        error: row.get(4)?,
        bootkit_detected: row.get::<_, i64>(5)? != 0,
        risk_score: row.get::<_, i64>(6)? as u32,
        risk_level: row.get(7)?,
        total_findings: row.get::<_, i64>(8)? as usize,
        critical_count: row.get::<_, i64>(9)? as usize,
        high_count: row.get::<_, i64>(10)? as usize,
        medium_count: row.get::<_, i64>(11)? as usize,
        low_count: row.get::<_, i64>(12)? as usize,
        info_count: row.get::<_, i64>(13)? as usize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use barzakh_core::scanner::ScanInfo;
    use barzakh_core::{Finding, RiskScore, ScanSummary, Severity};

    fn sample_result(target: &str, findings: Vec<Finding>) -> ScanResult {
        let risk = RiskScore::from_findings(&findings);
        let critical_count = findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        ScanResult {
            summary: ScanSummary {
                total_findings: findings.len(),
                critical_count,
                high_count: 0,
                medium_count: 0,
                low_count: 0,
                info_count: 0,
                bootkit_detected: critical_count > 0,
            },
            findings,
            scan_info: ScanInfo {
                target: target.to_string(),
                start_time: "2026-10-13T10:00:00+00:00".to_string(),
                end_time: "2026-10-13T10:00:01+00:00".to_string(),
                duration_seconds: 1.0,
            },
            risk,
        }
    }

    #[test]
    fn record_list_get_round_trip() {
        let mut store = ScanStore::open(Path::new(":memory:")).unwrap();
        let result = sample_result(
            "/tmp/fw.bin",
            vec![Finding::new("blacklotus", Severity::Critical, "BL", "d")],
        );
        let id = store.record(&result).unwrap();
        assert_eq!(id, 1);

        let records = store.list(10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target, "/tmp/fw.bin");
        assert!(records[0].bootkit_detected);
        assert_eq!(records[0].critical_count, 1);

        let findings = store.get_findings(id).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].detector, "blacklotus");
    }

    #[test]
    fn diff_detects_new_and_resolved() {
        let mut store = ScanStore::open(Path::new(":memory:")).unwrap();
        let a = store
            .record(&sample_result(
                "fw",
                vec![
                    Finding::new("hook", Severity::High, "H1", "d"),
                    Finding::new("entropy", Severity::Medium, "E1", "d"),
                ],
            ))
            .unwrap();
        let b = store
            .record(&sample_result(
                "fw",
                vec![
                    Finding::new("hook", Severity::High, "H1", "d"),
                    Finding::new("smm", Severity::Critical, "S1", "d"),
                ],
            ))
            .unwrap();

        let diff = store.diff(a, b).unwrap();
        let new: Vec<&DiffEntry> = diff.iter().filter(|d| d.status == "new").collect();
        let resolved: Vec<&DiffEntry> = diff.iter().filter(|d| d.status == "resolved").collect();
        assert_eq!(new.len(), 1);
        assert_eq!(new[0].detector, "smm");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].detector, "entropy");
    }

    #[test]
    fn trends_aggregate_by_day() {
        let mut store = ScanStore::open(Path::new(":memory:")).unwrap();
        store
            .record(&sample_result(
                "fw",
                vec![Finding::new("hook", Severity::High, "H", "d")],
            ))
            .unwrap();
        store.record(&sample_result("fw", vec![])).unwrap();
        let trends = store.trends().unwrap();
        assert_eq!(trends.len(), 1);
        assert_eq!(trends[0].scans, 2);
        assert_eq!(trends[0].total_findings, 1);
    }

    #[test]
    fn missing_scan_errors() {
        let store = ScanStore::open(Path::new(":memory:")).unwrap();
        assert!(store.get(999).is_err());
    }

    #[test]
    fn pending_complete_fail_lifecycle() {
        let mut store = ScanStore::open(Path::new(":memory:")).unwrap();

        // Pending row is pollable with status running.
        let id = store.record_pending("/tmp/fw.bin").unwrap();
        assert_eq!(store.get(id).unwrap().status, "running");

        // Completing fills in the result.
        let result = sample_result(
            "/tmp/fw.bin",
            vec![Finding::new("blacklotus", Severity::Critical, "BL", "d")],
        );
        store.complete(id, &result).unwrap();
        let record = store.get(id).unwrap();
        assert_eq!(record.status, "complete");
        assert!(record.bootkit_detected);
        assert_eq!(record.critical_count, 1);
        assert!(record.error.is_none());
        assert_eq!(store.get_findings(id).unwrap().len(), 1);

        // Failing marks a running scan failed with the error message.
        let failed = store.record_pending("/tmp/other.bin").unwrap();
        store.fail(failed, "scan worker panicked").unwrap();
        let record = store.get(failed).unwrap();
        assert_eq!(record.status, "failed");
        assert_eq!(record.error.as_deref(), Some("scan worker panicked"));

        // Sync record() still produces complete rows.
        let sync = store.record(&result).unwrap();
        assert_eq!(store.get(sync).unwrap().status, "complete");
    }

    #[test]
    fn migrates_pre_status_databases() {
        // A database created before the status column existed.
        let dir = std::env::temp_dir().join(format!(
            "barzakh-store-migration-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("old.db");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    target TEXT NOT NULL,
                    bootkit_detected INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    critical_count INTEGER NOT NULL,
                    high_count INTEGER NOT NULL,
                    medium_count INTEGER NOT NULL,
                    low_count INTEGER NOT NULL,
                    info_count INTEGER NOT NULL,
                    findings_json TEXT NOT NULL
                );
                INSERT INTO scans (ts, target, bootkit_detected, risk_score, risk_level,
                    total_findings, critical_count, high_count, medium_count, low_count,
                    info_count, findings_json)
                VALUES ('2026-01-01', '/fw', 0, 10, 'low', 1, 0, 0, 1, 0, 0, '[]');",
            )
            .unwrap();
        }

        // Reopening migrates in place; old rows read back as complete.
        let store = ScanStore::open(&db).unwrap();
        let record = store.get(1).unwrap();
        assert_eq!(record.status, "complete");
        assert_eq!(record.target, "/fw");

        // And new async rows work on the migrated schema.
        let mut store = store;
        let id = store.record_pending("/fw").unwrap();
        assert_eq!(store.get(id).unwrap().status, "running");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
