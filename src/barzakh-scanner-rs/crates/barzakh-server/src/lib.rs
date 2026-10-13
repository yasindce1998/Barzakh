//! REST API and web dashboard for the Barzakh firmware security platform.

pub mod api;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Mutex;

use barzakh_store::history::ScanStore;
use barzakh_store::kb::KnowledgeBase;

/// Server configuration.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub port: u16,
    pub db_path: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            port: 8420,
            db_path: PathBuf::from("barzakh.db"),
        }
    }
}

/// A scheduled recurring scan.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Schedule {
    pub target: String,
    pub interval_secs: u64,
    /// Instant of the next run (epoch seconds).
    pub next_run: u64,
    /// Number of runs so far.
    pub runs: u64,
}

/// Shared application state.
pub struct AppState {
    pub store: Mutex<ScanStore>,
    pub kb: Mutex<KnowledgeBase>,
    pub schedules: Mutex<Vec<Schedule>>,
}

/// Run the server until shutdown.
pub async fn run_server(config: ServerConfig) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let state = Arc::new(AppState {
        store: Mutex::new(ScanStore::open(&config.db_path)?),
        kb: Mutex::new(KnowledgeBase::open(&config.db_path)?),
        schedules: Mutex::new(Vec::new()),
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

    let due: Vec<String> = {
        let schedules = state.schedules.lock().await;
        schedules
            .iter()
            .filter(|s| s.next_run <= now)
            .map(|s| s.target.clone())
            .collect()
    };

    for target in due {
        let path = std::path::PathBuf::from(&target);
        let mut scanner = barzakh_core::BarzakhScanner::new(None);
        let result = scanner.scan(&path, None);
        {
            let mut store = state.store.lock().await;
            match store.record(&result) {
                Ok(id) => {
                    tracing::info!(
                        "scheduled scan of {target} recorded (#{id}, risk {})",
                        result.risk.score
                    );
                }
                Err(error) => {
                    tracing::warn!("recording scheduled scan of {target} failed: {error}");
                }
            }
        }

        let mut schedules = state.schedules.lock().await;
        if let Some(schedule) = schedules.iter_mut().find(|s| s.target == target) {
            schedule.runs += 1;
            schedule.next_run += schedule.interval_secs;
        }
    }

    Ok(())
}
