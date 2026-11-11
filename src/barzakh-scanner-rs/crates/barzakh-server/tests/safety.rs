use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use barzakh_server::{api, AppState, ServerConfig};
use barzakh_store::{history::ScanStore, kb::KnowledgeBase};
use std::sync::Arc;
use tower::ServiceExt;

fn state(root: &std::path::Path) -> Arc<AppState> {
    Arc::new(AppState {
        store: tokio::sync::Mutex::new(ScanStore::open(std::path::Path::new(":memory:")).unwrap()),
        kb: tokio::sync::Mutex::new(KnowledgeBase::open(std::path::Path::new(":memory:")).unwrap()),
        schedules: tokio::sync::Mutex::new(Vec::new()),
        payloads_dir: root.into(),
        api_key: None,
        scan_roots: vec![root.canonicalize().unwrap()],
        max_image_bytes: 1024,
        scan_workers: Arc::new(tokio::sync::Semaphore::new(1)),
        scan_slots: Arc::new(tokio::sync::Semaphore::new(1)),
    })
}

#[test]
fn authentication_is_mandatory_except_explicit_loopback_development() {
    let mut config = ServerConfig::default();
    assert!(config.bind.is_loopback());
    assert!(config.validate().is_err());
    config.insecure_dev = true;
    assert!(config.validate().is_ok());
    config.bind = "0.0.0.0".parse().unwrap();
    assert!(config.validate().is_err());
    config.api_key = Some("test-secret".into());
    assert!(config.validate().is_ok());
    config.api_key = Some(" ".into());
    assert!(config.validate().is_err());
}

#[tokio::test]
async fn rejects_outside_roots_special_files_and_oversized_images() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(outside.path(), [0u8; 32]).unwrap();
    let state = state(root.path());
    assert!(barzakh_server::validate_target(&state, outside.path()).is_err());
    assert!(barzakh_server::validate_target(&state, root.path()).is_err());
    let large = root.path().join("large");
    std::fs::write(&large, [0u8; 2048]).unwrap();
    assert!(barzakh_server::validate_target(&state, &large).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(outside.path(), root.path().join("escape")).unwrap();
        assert!(barzakh_server::validate_target(&state, &root.path().join("escape")).is_err());
    }
    let response = api::router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scans")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"target": outside.path()}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn queue_overload_returns_429_without_creating_a_scan() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("fw.bin");
    std::fs::write(&target, [0u8; 64]).unwrap();
    let state = state(root.path());
    let _held = state.scan_slots.acquire().await.unwrap();
    let response = api::router(Arc::clone(&state))
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scans")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({"target": target}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(state.store.lock().await.count().unwrap(), 0);
}

#[tokio::test]
async fn queued_target_removed_before_worker_runs_is_recorded_failed() {
    let root = tempfile::tempdir().unwrap();
    let target = root.path().join("fw.bin");
    std::fs::write(&target, [0u8; 64]).unwrap();
    let state = state(root.path());
    let held = Arc::clone(&state.scan_workers)
        .acquire_owned()
        .await
        .unwrap();
    let id = barzakh_server::enqueue_scan(Arc::clone(&state), target.display().to_string())
        .await
        .unwrap();
    std::fs::remove_file(&target).unwrap();
    drop(held);
    let status = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let record = state.store.lock().await.get(id).unwrap();
            if record.status != "running" {
                break record.status;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(status, "failed");
}
