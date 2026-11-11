//! REST API and web dashboard for the Barzakh firmware security platform.

pub mod api;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::{Mutex, Semaphore};

use barzakh_store::history::ScanStore;
use barzakh_store::kb::KnowledgeBase;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind: IpAddr,
    /// Unauthenticated development is permitted only on loopback.
    pub insecure_dev: bool,
    pub scan_roots: Vec<PathBuf>,
    pub max_image_bytes: u64,
    pub max_concurrent_scans: usize,
    pub max_queued_scans: usize,
    pub port: u16,
    pub db_path: PathBuf,
    /// Directory where `/api/adversary/generate` materializes payload images.
    pub payloads_dir: PathBuf,
    /// API key required by every authenticated `/api/*` endpoint
    /// (`X-API-Key: <key>` or `Authorization: Bearer <key>`). `None`
    /// is accepted only with explicit loopback development mode.
    pub api_key: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            insecure_dev: false,
            scan_roots: vec![PathBuf::from("payloads")],
            max_image_bytes: barzakh_core::context::DEFAULT_MAX_IMAGE_BYTES,
            max_concurrent_scans: 2,
            max_queued_scans: 8,
            port: 8420,
            db_path: PathBuf::from("barzakh.db"),
            payloads_dir: PathBuf::from("payloads"),
            api_key: None,
        }
    }
}

impl ServerConfig {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.api_key
                .as_ref()
                .is_none_or(|key| !key.trim().is_empty()),
            "API key cannot be empty"
        );
        anyhow::ensure!(self.api_key.is_some() || (self.insecure_dev && self.bind.is_loopback()),
            "authentication required: configure --api-key/BARZAKH_API_KEY, or use --insecure-dev on loopback only");
        anyhow::ensure!(
            !self.scan_roots.is_empty(),
            "at least one --scan-root is required"
        );
        anyhow::ensure!(
            self.max_image_bytes > 0 && self.max_concurrent_scans > 0,
            "image size and scan concurrency limits must be positive"
        );
        anyhow::ensure!(
            self.max_concurrent_scans <= 64 && self.max_queued_scans <= 1024,
            "scan concurrency/queue limits exceed supported bounds"
        );
        Ok(())
    }
}

/// A scheduled recurring scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Schedule {
    pub id: u64,
    pub target: String,
    pub interval_secs: u64,
    /// Instant of the next run (epoch seconds).
    pub next_run: u64,
    /// Number of runs so far.
    pub runs: u64,
}

/// Shared application state.
pub struct AppState {
    pub scan_roots: Vec<PathBuf>,
    pub max_image_bytes: u64,
    pub scan_workers: Arc<Semaphore>,
    pub scan_slots: Arc<Semaphore>,
    pub store: Mutex<ScanStore>,
    pub kb: Mutex<KnowledgeBase>,
    pub schedules: Mutex<Vec<Schedule>>,
    pub payloads_dir: PathBuf,
    /// When set, all `/api/*` requests (except `/api/health`) must
    /// authenticate with this key.
    pub api_key: Option<String>,
}

/// Run the server until shutdown.
pub async fn run_server(config: ServerConfig) -> Result<()> {
    config.validate()?;
    let addr = SocketAddr::from((config.bind, config.port));
    if config.api_key.is_none() {
        tracing::warn!(
            "API authentication is DISABLED: every /api endpoint is reachable \
             without credentials. Set --api-key or BARZAKH_API_KEY to require \
             an API key."
        );
    }
    std::fs::create_dir_all(&config.payloads_dir)?;
    let scan_roots = config
        .scan_roots
        .iter()
        .map(std::fs::canonicalize)
        .collect::<std::io::Result<Vec<_>>>()?;
    anyhow::ensure!(
        scan_roots.iter().all(|p| p.is_dir()),
        "scan roots must be directories"
    );
    let state = Arc::new(AppState {
        scan_roots,
        max_image_bytes: config.max_image_bytes,
        scan_workers: Arc::new(Semaphore::new(config.max_concurrent_scans)),
        scan_slots: Arc::new(Semaphore::new(
            config.max_concurrent_scans + config.max_queued_scans,
        )),
        store: Mutex::new(ScanStore::open(&config.db_path)?),
        kb: Mutex::new(KnowledgeBase::open(&config.db_path)?),
        schedules: Mutex::new(Vec::new()),
        payloads_dir: config.payloads_dir.clone(),
        api_key: config.api_key.clone(),
    });
    // Background scheduler: run due scheduled scans every 30 seconds.
    let scheduler_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Err(error) = run_due_scans(&scheduler_state).await {
                tracing::warn!("scheduled scan failed: {error}");
            }
        }
    });

    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("barzakh-server listening on http://{addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Execute every scheduled scan whose deadline has passed.
async fn run_due_scans(state: &Arc<AppState>) -> anyhow::Result<()> {
    let now = chrono::Utc::now().timestamp().max(0) as u64;

    let due: Vec<(u64, String)> = {
        let schedules = state.schedules.lock().await;
        schedules
            .iter()
            .filter(|s| s.next_run <= now)
            .map(|s| (s.id, s.target.clone()))
            .collect()
    };

    for (id, target) in due {
        if let Err(error) = enqueue_scan(Arc::clone(state), target.clone()).await {
            tracing::warn!("scheduled scan of {target} rejected: {error}");
        }
        let mut schedules = state.schedules.lock().await;
        if let Some(schedule) = schedules.iter_mut().find(|s| s.id == id) {
            schedule.runs += 1;
            schedule.next_run = now.saturating_add(schedule.interval_secs);
        }
    }

    Ok(())
}

/// Constrain all API file reads, including KB profiling and scheduled scans.
/// Scan roots must not be writable by untrusted local users (see DEPLOYMENT.md).
pub fn validate_target(state: &AppState, target: &std::path::Path) -> Result<PathBuf> {
    let path = std::fs::canonicalize(target)?;
    anyhow::ensure!(
        state.scan_roots.iter().any(|root| path.starts_with(root)),
        "target is outside approved scan roots"
    );
    let meta = std::fs::metadata(&path)?;
    anyhow::ensure!(meta.is_file(), "target must be a regular file");
    anyhow::ensure!(
        meta.len() > 0 && meta.len() <= state.max_image_bytes,
        "invalid or oversized image"
    );
    Ok(path)
}

/// One bounded queue shared by manual and scheduled scans. A slot is held
/// through persistence; the worker permit is held by the blocking closure.
pub async fn enqueue_scan(state: Arc<AppState>, target: String) -> Result<i64> {
    let slot = Arc::clone(&state.scan_slots)
        .try_acquire_owned()
        .map_err(|_| anyhow::anyhow!("scan queue is full"))?;
    let path = validate_target(&state, std::path::Path::new(&target))?;
    let id = state
        .store
        .lock()
        .await
        .record_pending(&path.display().to_string())?;
    tokio::spawn(async move {
        let _slot = slot;
        let permit = Arc::clone(&state.scan_workers).acquire_owned().await;
        let result = match permit {
            Ok(permit) => {
                let worker_state = Arc::clone(&state);
                tokio::task::spawn_blocking(move || -> Result<barzakh_core::ScanResult> {
                    let _permit = permit;
                    let path = validate_target(&worker_state, &path)?;
                    let context = barzakh_core::ScanContext::load_with_limit(
                        &path,
                        worker_state.max_image_bytes,
                    )?;
                    let mut scanner = barzakh_core::BarzakhScanner::new(None);
                    scanner.max_image_bytes = worker_state.max_image_bytes;
                    Ok(scanner.scan_context(&context, None))
                })
                .await
                .map_err(anyhow::Error::from)
                .and_then(|r| r)
            }
            Err(error) => Err(error.into()),
        };
        let mut store = state.store.lock().await;
        let saved = match result {
            Ok(scan) => store.complete(id, &scan),
            Err(error) => store.fail(id, &error.to_string()),
        };
        if let Err(error) = saved {
            tracing::error!("saving scan {id}: {error}");
        }
    });
    Ok(id)
}
