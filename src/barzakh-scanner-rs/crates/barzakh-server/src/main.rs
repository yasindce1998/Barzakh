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
    let mut explicit_scan_roots = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                config.bind = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--bind requires an IP address"))?
                    .parse()?
            }
            "--insecure-dev" => config.insecure_dev = true,
            "--scan-root" => {
                let root = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--scan-root requires a directory"))?;
                if !explicit_scan_roots {
                    config.scan_roots.clear();
                    explicit_scan_roots = true;
                }
                config.scan_roots.push(root.into());
            }
            "--max-image-bytes" => {
                config.max_image_bytes = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing byte limit"))?
                    .parse()?
            }
            "--max-concurrent-scans" => {
                config.max_concurrent_scans = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing concurrency limit"))?
                    .parse()?
            }
            "--max-queued-scans" => {
                config.max_queued_scans = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("missing queue limit"))?
                    .parse()?
            }
            "--port" => {
                config.port = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--port requires a number"))?
                    .parse()?;
            }
            "--db" => {
                config.db_path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--db requires a path"))?
                    .into();
            }
            "--payloads-dir" => {
                config.payloads_dir = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--payloads-dir requires a directory"))?
                    .into();
            }
            "--api-key" => {
                config.api_key = Some(
                    args.next()
                        .ok_or_else(|| anyhow::anyhow!("--api-key requires a nonempty key"))?,
                );
            }
            "--help" | "-h" => {
                println!(
                    "barzakh-server — REST API and web dashboard\n\n\
                     Usage: barzakh-server [--port 8420] [--db barzakh.db] \
                     [--payloads-dir payloads] [--api-key KEY]\n\n\
                     Authentication: pass --api-key (or set BARZAKH_API_KEY) to require \
                     an API key on every /api endpoint except /api/health, via the \
                     X-API-Key or Authorization: Bearer header. Without it the server \
                     refuses to start unless --insecure-dev is explicitly set on loopback.\n\n\
                     Safety: --bind 127.0.0.1, --scan-root DIR (repeatable; default payloads),\n\
                     --max-image-bytes 536870912, --max-concurrent-scans 2, --max-queued-scans 8.\n\n\
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
