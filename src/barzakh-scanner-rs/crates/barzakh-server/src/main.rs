use anyhow::Result;

use barzakh_server::ServerConfig;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut config = ServerConfig::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                config.port = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(config.port);
            }
            "--db" => {
                if let Some(db) = args.next() {
                    config.db_path = db.into();
                }
            }
            "--payloads-dir" => {
                if let Some(dir) = args.next() {
                    config.payloads_dir = dir.into();
                }
            }
            "--api-key" => {
                if let Some(key) = args.next() {
                    config.api_key = Some(key);
                }
            }
            "--help" | "-h" => {
                println!(
                    "barzakh-server — REST API and web dashboard\n\n\
                     Usage: barzakh-server [--port 8420] [--db barzakh.db] \
                     [--payloads-dir payloads] [--api-key KEY]\n\n\
                     Authentication: pass --api-key (or set BARZAKH_API_KEY) to require \
                     an API key on every /api endpoint except /api/health, via the \
                     X-API-Key or Authorization: Bearer header. Without it the server \
                     logs a warning and serves unauthenticated.\n\n\
                     Endpoints: GET / (dashboard), /api/health, /api/detectors, /api/scans,\n\
                     POST /api/scans {{\"target\": \"<firmware path>\"}}, GET /api/scans/{{id}},\n\
                     GET /api/scans/{{id}}/report?format=json|html|markdown|sarif|csv,\n\
                     GET /api/scans/diff?a=N&b=M, GET /api/trends, GET|POST /api/kb,\n\
                     POST /api/adversary/generate, GET /api/scenarios, GET|POST /api/schedule"
                );
                return Ok(());
            }
            other => {
                anyhow::bail!("unknown argument '{other}' (see --help)");
            }
        }
    }

    // Environment override: BARZAKH_API_KEY enables authentication.
    if config.api_key.is_none() {
        config.api_key = std::env::var("BARZAKH_API_KEY")
            .ok()
            .filter(|k| !k.is_empty());
    }

    barzakh_server::run_server(config).await
}
