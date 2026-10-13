//! HTTP API routes and the embedded dashboard.

use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use barzakh_core::ReportFormat;
use barzakh_store::kb::FirmwareProfile;

use crate::{AppState, Schedule};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/api/health", get(health))
        .route("/api/detectors", get(list_detectors))
        .route("/api/scans", post(submit_scan).get(list_scans))
        .route("/api/scans/:id", get(get_scan))
        .route("/api/scans/:id/report", get(scan_report))
        .route("/api/scans/diff", get(diff_scans))
        .route("/api/trends", get(trends))
        .route("/api/kb", get(list_kb).post(add_kb))
        .route("/api/adversary/generate", post(generate_payload))
        .route("/api/scenarios", get(list_scenarios))
        .route("/api/schedule", get(list_schedules).post(add_schedule))
        .with_state(state)
}

// ─── Basic endpoints ────────────────────────────────────────────────────────

async fn health(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let scans = {
        let store = state.store.lock().await;
        store.count().map_err(|e| scan_error(e.to_string()))?
    };
    Ok(Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "scans": scans,
    })))
}

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("../dashboard/index.html"))
}

async fn list_detectors() -> Json<serde_json::Value> {
    let scanner = barzakh_core::BarzakhScanner::new(None);
    Json(serde_json::json!({
        "count": scanner.detector_count(),
        "detectors": scanner.detector_names(),
    }))
}

// ─── Scans ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct SubmitScan {
    target: String,
}

#[derive(Debug, Serialize)]
struct ScanSubmitted {
    scan_id: i64,
    status: &'static str,
    risk_score: u32,
    bootkit_detected: bool,
}

async fn submit_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<SubmitScan>,
) -> Result<(StatusCode, Json<ScanSubmitted>), (StatusCode, Json<serde_json::Value>)> {
    let path = PathBuf::from(&request.target);
    let mut scanner = barzakh_core::BarzakhScanner::new(None);
    let result = scanner.scan(&path, None);

    let mut store = state.store.lock().await;
    let scan_id = store
        .record(&result)
        .map_err(|e| scan_error(e.to_string()))?;

    Ok((
        StatusCode::CREATED,
        Json(ScanSubmitted {
            scan_id,
            status: "complete",
            risk_score: result.risk.score,
            bootkit_detected: result.summary.bootkit_detected,
        }),
    ))
}

/// Render a scan record with the documented API field names.
fn record_json(record: &barzakh_store::history::ScanRecord) -> serde_json::Value {
    serde_json::json!({
        "scan_id": record.id,
        "target": record.target,
        "status": "complete",
        "bootkit_detected": record.bootkit_detected,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "total_findings": record.total_findings,
        "critical": record.critical_count,
        "high": record.high_count,
        "medium": record.medium_count,
        "low": record.low_count,
        "info": record.info_count,
        "timestamp": record.timestamp,
    })
}

async fn list_scans(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().await;
    let records = store.list(100).map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "scans": records.iter().map(record_json).collect::<Vec<_>>(),
    })))
}

async fn get_scan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().await;
    let record = store.get(id).map_err(|_| not_found(id))?;
    let findings = store
        .get_findings(id)
        .map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "scan_id": record.id,
        "target": record.target,
        "status": "complete",
        "bootkit_detected": record.bootkit_detected,
        "risk_score": record.risk_score,
        "risk_level": record.risk_level,
        "summary": {
            "total_findings": record.total_findings,
            "critical": record.critical_count,
            "high": record.high_count,
            "medium": record.medium_count,
            "low": record.low_count,
            "info": record.info_count,
        },
        "timestamp": record.timestamp,
        "findings": findings,
    })))
}

#[derive(Debug, Deserialize)]
struct ReportQuery {
    format: Option<String>,
}

async fn scan_report(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Query(query): Query<ReportQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let format = query.format.as_deref().unwrap_or("json");
    let Some(format) = ReportFormat::from_str(format) else {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("unknown format '{format}' (json|html|markdown|sarif|csv)"),
            })),
        ));
    };

    let store = state.store.lock().await;
    let findings = store.get_findings(id).map_err(|_| not_found(id))?;
    let record = store.get(id).map_err(|_| not_found(id))?;

    let generator =
        barzakh_core::reports::ReportGenerator::new(&findings, None).with_target(&record.target);
    let dir = tempfile_dir();
    let path = dir.join(format!("report-{id}"));
    generator
        .generate(&path, format)
        .map_err(|e| scan_error(e.to_string()))?;
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    Ok(Json(serde_json::json!({
        "scan_id": id,
        "format": format!("{format:?}").to_lowercase(),
        "content": content,
    })))
}

#[derive(Debug, Deserialize)]
struct DiffQuery {
    a: i64,
    b: i64,
}

async fn diff_scans(
    State(state): State<Arc<AppState>>,
    Query(query): Query<DiffQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().await;
    let entries = store
        .diff(query.a, query.b)
        .map_err(|e| scan_error(e.to_string()))?;
    let older = store.get(query.a).map_err(|_| not_found(query.a))?;
    let newer = store.get(query.b).map_err(|_| not_found(query.b))?;

    let to_json = |entries: Vec<barzakh_store::history::DiffEntry>| {
        entries
            .into_iter()
            .map(|entry| {
                serde_json::json!({
                    "detector": entry.detector,
                    "title": entry.title,
                    "severity": entry.severity,
                })
            })
            .collect::<Vec<_>>()
    };
    let (new_findings, resolved_findings) =
        entries.into_iter().partition(|entry| entry.status == "new");

    Ok(Json(serde_json::json!({
        "a": query.a,
        "b": query.b,
        "new_findings": to_json(new_findings),
        "resolved_findings": to_json(resolved_findings),
        "risk_score_delta": newer.risk_score as i64 - older.risk_score as i64,
    })))
}

async fn trends(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().await;
    let points = store.trends().map_err(|e| scan_error(e.to_string()))?;
    let top = store
        .top_detectors(10)
        .map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "trend": points
            .into_iter()
            .map(|point| serde_json::json!({
                "date": point.day,
                "scans": point.scans,
                "avg_risk_score": point.mean_risk,
                "total_findings": point.total_findings,
                "critical_findings": point.critical_findings,
            }))
            .collect::<Vec<_>>(),
        "top_detectors": top
            .into_iter()
            .map(|(detector, hits)| serde_json::json!({
                "detector": detector,
                "hits": hits,
            }))
            .collect::<Vec<_>>(),
    })))
}

// ─── Knowledge base ─────────────────────────────────────────────────────────

async fn list_kb(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let kb = state.kb.lock().await;
    let profiles = kb.list().map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({ "profiles": profiles })))
}

/// Slim KB creation request — the server profiles the target image itself.
#[derive(Debug, Deserialize)]
struct AddKbRequest {
    target: String,
    #[serde(default)]
    vendor: Option<String>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    family: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    arch: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    known_clean: bool,
}

async fn add_kb(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AddKbRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let image = std::fs::read(&request.target).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("reading {}: {e}", request.target),
            })),
        )
    })?;
    let mut profile = FirmwareProfile::from_image(&image);
    profile.vendor = request.vendor.unwrap_or_default();
    profile.device = request.device.unwrap_or_default();
    profile.family = request.family;
    profile.version = request.version;
    profile.arch = request.arch;
    profile.notes = request.notes;
    profile.known_clean = request.known_clean;

    let sha256 = profile.sha256.clone();
    let size = profile.size;
    let kb = state.kb.lock().await;
    kb.upsert(&profile).map_err(|e| scan_error(e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "recorded",
            "sha256": sha256,
            "size": size,
        })),
    ))
}

// ─── Adversary ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GenerateRequest {
    payload: String,
    arch: Option<String>,
    size: Option<usize>,
}

async fn generate_payload(
    State(state): State<Arc<AppState>>,
    Json(request): Json<GenerateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let payloads = barzakh_adversary::create_all_payloads();
    let payload = payloads
        .iter()
        .find(|p| p.name() == request.payload)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": format!("unknown payload '{}'", request.payload),
                    "available": payloads.iter().map(|p| p.name().to_string()).collect::<Vec<_>>(),
                })),
            )
        })?;

    let arch = match request.arch.as_deref() {
        Some("x86_64") => barzakh_adversary::Arch::X86_64,
        Some("aarch64") => barzakh_adversary::Arch::Aarch64,
        Some("riscv64") => barzakh_adversary::Arch::RiscV64,
        Some("power64") => barzakh_adversary::Arch::Power64,
        Some("armv7") => barzakh_adversary::Arch::Armv7,
        other => {
            if let Some(unknown) = other {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!(
                            "unknown arch '{unknown}' (x86_64|aarch64|riscv64|power64|armv7)"
                        ),
                    })),
                ));
            }
            barzakh_adversary::Arch::X86_64
        }
    };
    let arch_name = match arch {
        barzakh_adversary::Arch::X86_64 => "x86_64",
        barzakh_adversary::Arch::Aarch64 => "aarch64",
        barzakh_adversary::Arch::RiscV64 => "riscv64",
        barzakh_adversary::Arch::Power64 => "power64",
        barzakh_adversary::Arch::Armv7 => "armv7",
    };
    let size = request.size.unwrap_or(0x10000);
    let config = barzakh_adversary::PayloadConfig { arch, size };
    let data = payload
        .generate(&config)
        .map_err(|e| scan_error(e.to_string()))?;

    use sha2::Digest;
    let sha256 = {
        use sha2::Sha256;
        let digest = Sha256::digest(&data);
        digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    std::fs::create_dir_all(&state.payloads_dir).map_err(|e| scan_error(e.to_string()))?;
    let path = state.payloads_dir.join(format!(
        "{}-{arch_name}-{}.bin",
        request.payload,
        data.len()
    ));
    std::fs::write(&path, &data).map_err(|e| scan_error(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "payload": request.payload,
            "arch": arch_name,
            "size": data.len(),
            "sha256": sha256,
            "path": path.display().to_string(),
        })),
    ))
}

async fn list_scenarios() -> Json<serde_json::Value> {
    let bundled = barzakh_adversary::scenario::bundled();
    Json(serde_json::json!({
        "scenarios": bundled
            .iter()
            .map(|(name, scenario)| serde_json::json!({
                "name": name,
                "description": scenario.scenario.description,
                "stages": scenario.stages.len(),
                "mitre": scenario.scenario.mitre,
                "chain": scenario.render_chain(),
            }))
            .collect::<Vec<_>>(),
    }))
}

// ─── Scheduling ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct AddSchedule {
    target: String,
    interval_secs: u64,
}

async fn add_schedule(
    State(state): State<Arc<AppState>>,
    Json(request): Json<AddSchedule>,
) -> (StatusCode, Json<serde_json::Value>) {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let mut schedules = state.schedules.lock().await;
    let schedule_id = schedules.len() as u64 + 1;
    let interval_secs = request.interval_secs.max(30);
    schedules.push(Schedule {
        id: schedule_id,
        target: request.target.clone(),
        interval_secs,
        next_run: now + interval_secs,
        runs: 0,
    });
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "status": "scheduled",
            "schedule_id": schedule_id,
            "target": request.target,
            "interval_secs": interval_secs,
        })),
    )
}

async fn list_schedules(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let schedules = state.schedules.lock().await;
    Json(serde_json::json!({ "schedules": *schedules }))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn scan_error(message: String) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({ "error": message })),
    )
}

fn not_found(id: i64) -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({ "error": format!("scan {id} not found") })),
    )
}

/// Temporary directory for report rendering.
fn tempfile_dir() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "barzakh-server-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn body_json(
        router: &mut Router,
        request: Request<Body>,
    ) -> (StatusCode, serde_json::Value) {
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            store: tokio::sync::Mutex::new(
                barzakh_store::history::ScanStore::open(std::path::Path::new(":memory:")).unwrap(),
            ),
            kb: tokio::sync::Mutex::new(
                barzakh_store::kb::KnowledgeBase::open(std::path::Path::new(":memory:")).unwrap(),
            ),
            schedules: tokio::sync::Mutex::new(Vec::new()),
            payloads_dir: std::env::temp_dir().join(format!(
                "barzakh-server-test-payloads-{}",
                std::process::id()
            )),
        })
    }

    #[tokio::test]
    async fn health_reports_scan_count() {
        let state = test_state();
        let mut router = router(state.clone());
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "ok");
        assert_eq!(json["scans"].as_u64().unwrap(), 0);
    }

    #[tokio::test]
    async fn detectors_lists_registry() {
        let mut router = router(test_state());
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/detectors")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["count"].as_u64().unwrap() > 100);
        assert!(json["detectors"].as_array().unwrap().len() > 100);
    }

    #[tokio::test]
    async fn dashboard_serves_html() {
        let router = router(test_state());
        let response = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unknown_scan_is_not_found() {
        let mut router = router(test_state());
        let (status, _) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/scans/999")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn submit_scan_records_and_lists() {
        let mut router = router(test_state());
        // A minimal image the scanner will accept (all zeros).
        let dir = std::env::temp_dir().join(format!("barzakh-server-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fw = dir.join("fw.bin");
        std::fs::write(&fw, vec![0u8; 4096]).unwrap();

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .method("POST")
                .uri("/api/scans")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "target": fw.display().to_string() }).to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "body: {json}");
        let scan_id = json["scan_id"].as_i64().unwrap();
        assert!(scan_id >= 1);
        assert_eq!(json["status"], "complete");

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/scans")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let scans = json["scans"].as_array().unwrap();
        assert_eq!(scans.len(), 1);
        assert_eq!(scans[0]["scan_id"].as_i64().unwrap(), scan_id);
        assert_eq!(scans[0]["status"], "complete");
        assert!(scans[0]["risk_score"].is_u64());
        assert!(scans[0]["critical"].is_u64());
        assert!(scans[0]["timestamp"].is_string());

        // Trends and diff over the recorded scan.
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/trends")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!json["trend"].as_array().unwrap().is_empty());
        assert!(json["top_detectors"].is_array());

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri(format!("/api/scans/diff?a={scan_id}&b={scan_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["a"].as_i64().unwrap(), scan_id);
        assert_eq!(json["b"].as_i64().unwrap(), scan_id);
        assert_eq!(json["new_findings"].as_array().unwrap().len(), 0);
        assert_eq!(json["resolved_findings"].as_array().unwrap().len(), 0);
        assert_eq!(json["risk_score_delta"].as_i64().unwrap(), 0);

        // Single-scan detail uses the documented flat shape.
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri(format!("/api/scans/{scan_id}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["scan_id"].as_i64().unwrap(), scan_id);
        assert!(json["summary"]["critical"].is_u64());
        assert!(json["findings"].is_array());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn kb_accepts_slim_request() {
        let state = test_state();
        let mut router = router(state.clone());
        let dir = std::env::temp_dir().join(format!("barzakh-server-kb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fw = dir.join("fw.bin");
        std::fs::write(&fw, vec![0xABu8; 8192]).unwrap();

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .method("POST")
                .uri("/api/kb")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "target": fw.display().to_string(),
                        "vendor": "ASUS",
                        "device": "PRIME Z690-A",
                        "notes": "golden baseline image",
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "body: {json}");
        assert_eq!(json["status"], "recorded");
        assert_eq!(json["sha256"].as_str().unwrap().len(), 64);
        assert_eq!(json["size"].as_u64().unwrap(), 8192);

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/kb")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["profiles"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn generate_writes_payload_image() {
        let state = test_state();
        let mut router = router(state.clone());
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .method("POST")
                .uri("/api/adversary/generate")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "payload": "trampoline", "arch": "x86_64", "size": 4096 })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "body: {json}");
        assert_eq!(json["payload"], "trampoline");
        assert_eq!(json["arch"], "x86_64");
        assert!(json["sha256"].as_str().unwrap().len() == 64);
        let path = json["path"].as_str().unwrap();
        let written = std::fs::read(path).unwrap();
        assert_eq!(written.len(), json["size"].as_u64().unwrap() as usize);
        let _ = std::fs::remove_dir_all(&state.payloads_dir);
    }

    #[tokio::test]
    async fn scenarios_list_bundled() {
        let mut router = router(test_state());
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/scenarios")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let scenarios = json["scenarios"].as_array().unwrap();
        assert!(scenarios.len() >= 3);
        assert!(scenarios[0]["stages"].as_u64().unwrap() >= 2);
    }

    #[tokio::test]
    async fn schedule_add_and_list() {
        let mut router = router(test_state());
        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .method("POST")
                .uri("/api/schedule")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({ "target": "/tmp/fw.bin", "interval_secs": 3600 })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED);
        assert!(json["schedule_id"].as_u64().unwrap() >= 1);
        assert_eq!(json["interval_secs"].as_u64().unwrap(), 3600);

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/schedule")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["schedules"].as_array().unwrap().len(), 1);
    }
}
