use anyhow::Result;

use barzakh_agent::{Agent, AgentConfig};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mut config = AgentConfig::default();
    let mut command = "run".to_string();
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "run" | "once" => command = arg,
            "--config" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
                config = AgentConfig::load(std::path::Path::new(&path))?;
            }
            "--interval" => {
                if let Some(v) = args.next().and_then(|v| v.parse().ok()) {
                    config.interval_secs = v;
                }
            }
            "--format" => {
                if let Some(v) = args.next() {
                    config.siem_format = v;
                }
            }
            "--output" => {
                if let Some(v) = args.next() {
                    config.output = v;
                }
            }
            "--target" => {
                if let Some(v) = args.next() {
                    config.targets.push(v);
                }
            }
            "--db" => {
                if let Some(v) = args.next() {
                    config.db = v.into();
                }
            }
            "--help" | "-h" => {
                println!(
                    "barzakh-agent — real-time firmware tampering monitoring\n\n\
                     Usage: barzakh-agent [run|once] [--config agent.toml] [overrides]\n\n\
                     Commands:\n  run   watch targets forever (default)\n  once  poll once, alert on changes, exit\n\n\
                     Overrides: --interval SECS, --format ecs|cef|leef, --output PATH|-,\n\
                     --target PATH (repeatable), --db PATH"
                );
                return Ok(());
            }
            other => {
                anyhow::bail!("unknown argument '{other}' (see --help)");
            }
        }
    }

    if config.targets.is_empty() {
        anyhow::bail!(
            "no targets configured — pass --target PATH or use a config file (see --help)"
        );
    }

    let mut agent = Agent::new(config);
    match command.as_str() {
        "once" => {
            agent.prime();
            // In `once` mode treat every target as changed and scan it once.
            for target in agent.config.targets.clone() {
                let change = barzakh_agent::TargetChange {
                    target,
                    kind: "startup",
                };
                let alerts = agent.scan_and_alert(&change)?;
                tracing::info!("{alerts} alerting findings");
            }
            Ok(())
        }
        _ => agent.run_forever(),
    }
}
