//! Reproducible full-sweep latency measurement on operator-supplied images.
//! cargo run --release -p barzakh-core --example benchmark_scan -- IMAGE [RUNS]
use barzakh_core::{BarzakhScanner, ScanStatus};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = std::path::PathBuf::from(
        args.next()
            .ok_or_else(|| anyhow::anyhow!("usage: benchmark_scan IMAGE [RUNS]"))?,
    );
    let runs: usize = args.next().unwrap_or_else(|| "10".into()).parse()?;
    anyhow::ensure!((2..=1000).contains(&runs), "RUNS must be 2..1000");
    let mut scanner = BarzakhScanner::new(None);
    let warmup = scanner.scan(&path, None);
    anyhow::ensure!(
        warmup.status == ScanStatus::Complete,
        "benchmark requires complete scans"
    );
    let mut timings = Vec::new();
    for _ in 0..runs {
        let result = scanner.scan(&path, None);
        anyhow::ensure!(
            result.status == ScanStatus::Complete,
            "scan became incomplete"
        );
        anyhow::ensure!(
            result.input_sha256 == warmup.input_sha256,
            "image changed during benchmark"
        );
        timings.push(result.scan_info.duration_seconds * 1000.0);
    }
    timings.sort_by(f64::total_cmp);
    let percentile = |p: f64| {
        timings[((runs as f64 * p).ceil() as usize)
            .saturating_sub(1)
            .min(runs - 1)]
    };
    let peak_rss_kib = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|line| {
                line.strip_prefix("VmHWM:")
                    .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            })
        });
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "target": path, "input_sha256": warmup.input_sha256,
            "image_bytes": std::fs::metadata(&path)?.len(), "runs": runs,
            "detectors": scanner.detector_count(), "p50_ms": percentile(0.50),
            "p95_ms": percentile(0.95), "peak_process_rss_kib": peak_rss_kib,
            "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
            "version": env!("CARGO_PKG_VERSION"), "includes_input_read_and_hash": true
        }))?
    );
    Ok(())
}
