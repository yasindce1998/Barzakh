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
            "--help" | "-h" => {
                println!(
                    "barzakh-server — REST API and web dashboard\n\n\
                     Usage: barzakh-server [--port 8420] [--db barzakh.db]\n\n\
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

    barzakh_server::run_server(config).await
}
