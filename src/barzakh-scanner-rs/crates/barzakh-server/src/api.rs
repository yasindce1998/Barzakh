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

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
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
            risk_score: result.risk.score,
            bootkit_detected: result.summary.bootkit_detected,
        }),
    ))
}

async fn list_scans(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().await;
    let records = store.list(100).map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({ "scans": records })))
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
        "record": record,
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
    let diff = store
        .diff(query.a, query.b)
        .map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({
        "older": query.a,
        "newer": query.b,
        "changes": diff,
    })))
}

async fn trends(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let store = state.store.lock().await;
    let trends = store.trends().map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({ "trends": trends })))
}

// ─── Knowledge base ─────────────────────────────────────────────────────────

async fn list_kb(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let kb = state.kb.lock().await;
    let profiles = kb.list().map_err(|e| scan_error(e.to_string()))?;
    Ok(Json(serde_json::json!({ "profiles": profiles })))
}

async fn add_kb(
    State(state): State<Arc<AppState>>,
    Json(profile): Json<FirmwareProfile>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let kb = state.kb.lock().await;
    kb.upsert(&profile).map_err(|e| scan_error(e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "recorded", "sha256": profile.sha256 })),
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
        Some("aarch64") => barzakh_adversary::Arch::Aarch64,
        Some("riscv64") => barzakh_adversary::Arch::RiscV64,
        Some("power64") => barzakh_adversary::Arch::Power64,
        Some("armv7") => barzakh_adversary::Arch::Armv7,
        _ => barzakh_adversary::Arch::X86_64,
    };
    let config = barzakh_adversary::PayloadConfig {
        arch,
        size: request.size.unwrap_or(0x10000),
    };
    let data = payload
        .generate(&config)
        .map_err(|e| scan_error(e.to_string()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "payload": request.payload,
            "size": data.len(),
            "data_base64": base64_encode(&data),
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
    schedules.push(Schedule {
        target: request.target.clone(),
        interval_secs: request.interval_secs.max(30),
        next_run: now + request.interval_secs.max(30),
        runs: 0,
    });
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "status": "scheduled", "target": request.target })),
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

fn base64_encode(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
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
        })
    }

    #[tokio::test]
    async fn health_reports_ok() {
        let mut router = router(test_state());
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

        let (status, json) = body_json(
            &mut router,
            Request::builder()
                .uri("/api/scans")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["scans"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
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
        let (status, _) = body_json(
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

    #[test]
    fn base64_matches_known_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }
}
