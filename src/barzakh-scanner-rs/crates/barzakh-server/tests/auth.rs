//! API-key authentication tests (Phase 0.3 of docs/ROADMAP.md).
//!
//! Exercises the router directly (tower `oneshot`): when an API key is
//! configured, unauthenticated and wrongly-authenticated requests are
//! rejected with 401, `X-API-Key` and `Authorization: Bearer` are both
//! accepted, `/api/health` stays open for probes, and a server without
//! a key serves unauthenticated (with a startup warning).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use barzakh_server::api;
use barzakh_server::AppState;
use barzakh_store::history::ScanStore;
use barzakh_store::kb::KnowledgeBase;
use http_body_util::BodyExt;
use tower::ServiceExt;

fn state(api_key: Option<String>) -> Arc<AppState> {
    let dir = tempfile::tempdir().unwrap().keep();
    let db = dir.join("test.db");
    Arc::new(AppState {
        scan_roots: vec![dir.canonicalize().unwrap()],
        max_image_bytes: 1024 * 1024,
        scan_workers: Arc::new(tokio::sync::Semaphore::new(2)),
        scan_slots: Arc::new(tokio::sync::Semaphore::new(4)),
        store: tokio::sync::Mutex::new(ScanStore::open(&db).unwrap()),
        kb: tokio::sync::Mutex::new(KnowledgeBase::open(&db).unwrap()),
        schedules: tokio::sync::Mutex::new(Vec::new()),
        payloads_dir: dir,
        api_key,
    })
}

async fn get_json(
    app: axum::Router,
    uri: &str,
    headers: &[(&'static str, String)],
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri(uri).method("GET");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    };
    (status, json)
}

#[tokio::test]
async fn api_key_required_when_configured() {
    let app = api::router(state(Some("correct-key".to_string())));

    // No credentials → 401.
    let (status, body) = get_json(app.clone(), "/api/detectors", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {body}");

    // Wrong key → 401.
    let (status, _) = get_json(
        app.clone(),
        "/api/detectors",
        &[("x-api-key", "wrong-key".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Correct key via X-API-Key → 200.
    let (status, _) = get_json(
        app.clone(),
        "/api/detectors",
        &[("x-api-key", "correct-key".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Correct key via Authorization: Bearer → 200.
    let (status, _) = get_json(
        app.clone(),
        "/api/detectors",
        &[("authorization", "Bearer correct-key".to_string())],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // POST endpoints are protected too.
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/scans")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"target":"/nonexistent"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn health_stays_open_when_configured() {
    let app = api::router(state(Some("correct-key".to_string())));
    let (status, body) = get_json(app, "/api/health", &[]).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn no_key_serves_unauthenticated() {
    let app = api::router(state(None));
    let (status, _) = get_json(app, "/api/detectors", &[]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn static_dashboard_can_load_before_entering_api_key() {
    let response = api::router(state(Some("correct-key".into())))
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("id=\"api-key\""));
}
