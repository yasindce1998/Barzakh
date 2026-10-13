use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use tabled::{Table, Tabled};
use tracing_subscriber::EnvFilter;

use barzakh_core::{BarzakhScanner, Baseline, ReportFormat, Severity};

#[derive(Parser)]
#[command(
    name = "barzakh",
    about = "Barzakh — UEFI Firmware Security Analysis Platform",
    long_about = "A comprehensive UEFI bootkit detection engine with 30 security detectors\n\
                  for firmware integrity verification and threat analysis.",
    version,
    propagate_version = true
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose/debug output
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a firmware image or memory dump for bootkits
    Scan(ScanArgs),

    /// Manage firmware baselines
    Baseline {
        #[command(subcommand)]
        command: BaselineCommands,
    },

    /// Generate scan reports
    Report(ReportArgs),

    /// Validate scanner detection accuracy against corpus
    Validate(ValidateArgs),

    /// List and inspect security detectors
    Detectors {
        #[command(subcommand)]
        command: DetectorCommands,
    },

    /// Display platform information and statistics
    Info,

    /// Run the automated fuzzing harness
    Fuzz(FuzzArgs),

    /// Browse recorded scan history (requires --history on scan)
    History {
        #[command(subcommand)]
        command: HistoryCommands,
    },

    /// Manage the firmware knowledge base
    Kb {
        #[command(subcommand)]
        command: KbCommands,
    },

    /// Threat-intelligence feeds, MISP export and ATT&CK mapping
    Intel {
        #[command(subcommand)]
        command: IntelCommands,
    },

    /// Train and evaluate ML models on labeled corpora
    Ml {
        #[command(subcommand)]
        command: MlCommands,
    },

    /// Serve the web dashboard and REST API
    Serve(ServeArgs),
}

// ─── Scan ────────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ScanArgs {
    /// Path to firmware image or memory dump
    #[arg(short, long)]
    target: PathBuf,

    /// Path to baseline configuration JSON
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Specific detector types to run (comma-separated)
    #[arg(long, value_delimiter = ',')]
    scan_types: Option<Vec<String>>,

    /// Output findings as JSON to stdout
    #[arg(long)]
    json: bool,

    /// Suppress progress output, only set exit code
    #[arg(short, long)]
    quiet: bool,

    /// Auto-generate report after scan
    #[arg(long)]
    report: Option<PathBuf>,

    /// Report format (json, html, markdown, sarif, csv, ecs, cef, leef)
    #[arg(long, default_value = "json")]
    format: String,

    /// Directory of TOML detection rules (declarative rule engine)
    #[arg(long)]
    rules_dir: Option<PathBuf>,

    /// IOC feed JSON (repeatable)
    #[arg(long = "ioc-feed")]
    ioc_feeds: Vec<PathBuf>,

    /// YARA rule file or directory (*.yar / *.yara)
    #[arg(long)]
    yara: Option<PathBuf>,

    /// Record the scan result into this history database
    #[arg(long)]
    history: Option<PathBuf>,

    /// Enable the ML anomaly detector (isolation forest)
    #[arg(long)]
    ml: bool,
}

// ─── Baseline ────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum BaselineCommands {
    /// Create a baseline from a known-good firmware image
    Create(BaselineCreateArgs),

    /// Display baseline contents
    Show(BaselineShowArgs),
}

#[derive(Parser)]
struct BaselineCreateArgs {
    /// Path to clean firmware image
    #[arg(short, long)]
    target: PathBuf,

    /// Output path for baseline JSON
    #[arg(short, long, default_value = "baseline.json")]
    output: PathBuf,

    /// `tpm2_pcrread` output captured from the reference machine
    #[arg(long)]
    pcrs: Option<PathBuf>,

    /// Memory-map dump (e.g. from a boot-services memory map print)
    #[arg(long)]
    memmap: Option<PathBuf>,

    /// TCG event log dump (one JSON object per line)
    #[arg(long)]
    eventlog: Option<PathBuf>,
}

#[derive(Parser)]
struct BaselineShowArgs {
    /// Path to baseline JSON file
    path: PathBuf,
}

// ─── Report ──────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ReportArgs {
    /// Path to firmware image to scan and report on
    #[arg(short, long)]
    target: PathBuf,

    /// Optional baseline
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Output path for report
    #[arg(short, long, default_value = "report.json")]
    output: PathBuf,

    /// Report format (json, html, markdown)
    #[arg(short, long, default_value = "json")]
    format: String,
}

// ─── Validate ────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ValidateArgs {
    /// Path to corpus directory
    #[arg(short, long)]
    corpus: PathBuf,

    /// Optional baseline JSON
    #[arg(short, long)]
    baseline: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

// ─── Fuzz ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct FuzzArgs {
    /// Number of mutation iterations
    #[arg(short, long, default_value = "1")]
    iterations: u32,

    /// Output directory for generated corpus
    #[arg(short, long, default_value = "./fuzz_corpus")]
    output_dir: PathBuf,

    /// Enable payload mutation
    #[arg(long)]
    mutate: bool,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Protocol-aware fuzzing target (dhcpv6, bmp, capsule, httpboot, tcg, hii)
    #[arg(long)]
    protocol: Option<String>,
}

// ─── History ─────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum HistoryCommands {
    /// List recent scans (newest first)
    List {
        /// History database path
        #[arg(long, default_value = "barzakh-history.sqlite")]
        db: PathBuf,
        /// Maximum number of scans to show
        #[arg(short, long, default_value = "20")]
        limit: usize,
    },
    /// Show one scan record and its findings
    Show {
        /// Scan id
        id: i64,
        /// History database path
        #[arg(long, default_value = "barzakh-history.sqlite")]
        db: PathBuf,
    },
    /// Diff two scans (new vs resolved findings)
    Diff {
        /// Older scan id
        a: i64,
        /// Newer scan id
        b: i64,
        /// History database path
        #[arg(long, default_value = "barzakh-history.sqlite")]
        db: PathBuf,
    },
    /// Daily trend aggregation
    Trends {
        /// History database path
        #[arg(long, default_value = "barzakh-history.sqlite")]
        db: PathBuf,
    },
}

// ─── Knowledge base ──────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum KbCommands {
    /// Record a firmware profile from an image
    Add {
        /// Firmware image to profile
        #[arg(short, long)]
        target: PathBuf,
        #[arg(long)]
        vendor: Option<String>,
        #[arg(long)]
        device: Option<String>,
        #[arg(long)]
        family: Option<String>,
        /// Firmware version string (e.g. "3607")
        #[arg(long = "fw-version")]
        fw_version: Option<String>,
        #[arg(long)]
        arch: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        /// Mark the image as verified known-clean
        #[arg(long)]
        known_clean: bool,
        /// Knowledge base path
        #[arg(long, default_value = "barzakh-kb.sqlite")]
        db: PathBuf,
    },
    /// List all profiles
    List {
        /// Knowledge base path
        #[arg(long, default_value = "barzakh-kb.sqlite")]
        db: PathBuf,
    },
    /// Search vendor/device/family/notes/hash prefixes
    Search {
        #[arg(short, long)]
        query: String,
        /// Knowledge base path
        #[arg(long, default_value = "barzakh-kb.sqlite")]
        db: PathBuf,
    },
    /// Export profiles as a shareable JSON bundle
    Export {
        #[arg(short, long)]
        output: PathBuf,
        /// Strip identifying vendor/device details
        #[arg(long)]
        anonymize: bool,
        /// Knowledge base path
        #[arg(long, default_value = "barzakh-kb.sqlite")]
        db: PathBuf,
    },
    /// Import a profile bundle
    Import {
        #[arg(short, long)]
        input: PathBuf,
        /// Knowledge base path
        #[arg(long, default_value = "barzakh-kb.sqlite")]
        db: PathBuf,
    },
}

// ─── Intel ───────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum IntelCommands {
    /// List IOC feeds in a directory
    Feeds {
        /// Directory containing feed JSON files
        #[arg(long, default_value = "intel-feeds")]
        dir: PathBuf,
    },
    /// Export a scan's findings as a MISP event
    Misp {
        /// Firmware image to scan
        #[arg(short, long)]
        target: PathBuf,
        /// Output path for the MISP event JSON
        #[arg(short, long, default_value = "misp-event.json")]
        output: PathBuf,
        /// Event title override
        #[arg(long)]
        title: Option<String>,
    },
    /// Map scan findings to MITRE ATT&CK techniques
    Attack {
        /// Firmware image to scan
        #[arg(short, long)]
        target: PathBuf,
    },
}

// ─── ML ──────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum MlCommands {
    /// Train the combined model on a labeled corpus
    Train {
        /// Corpus directory (malicious_*/clean_* files)
        #[arg(short, long)]
        corpus: PathBuf,
        /// Output path for model JSON
        #[arg(short, long, default_value = "model.json")]
        output: PathBuf,
    },
    /// Evaluate a model against a corpus (TPR/FPR, confusion matrix)
    Evaluate {
        /// Corpus directory (malicious_*/clean_* files)
        #[arg(short, long)]
        corpus: PathBuf,
        /// Trained model JSON
        #[arg(short, long)]
        model: PathBuf,
    },
}

// ─── Serve ───────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ServeArgs {
    /// TCP port to listen on
    #[arg(short, long, default_value = "8420")]
    port: u16,
    /// SQLite database path for scans and knowledge base
    #[arg(long, default_value = "barzakh.db")]
    db: PathBuf,
}

// ─── Detectors ───────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum DetectorCommands {
    /// List all available security detectors
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Show details about a specific detector
    Info {
        /// Detector name
        name: String,
    },
}

// ─── Table row types ─────────────────────────────────────────────────────────

#[derive(Tabled)]
struct DetectorRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Detector")]
    name: String,
}

#[derive(Tabled)]
struct FindingRow {
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Detector")]
    detector: String,
    #[tabled(rename = "Title")]
    title: String,
}

#[derive(Tabled)]
struct HistoryRow {
    #[tabled(rename = "#")]
    id: i64,
    #[tabled(rename = "Date")]
    timestamp: String,
    #[tabled(rename = "Target")]
    target: String,
    #[tabled(rename = "Risk")]
    risk: String,
    #[tabled(rename = "Verdict")]
    verdict: String,
    #[tabled(rename = "C/H/M/L/I")]
    findings: String,
}

#[derive(Tabled)]
struct DiffRow {
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Detector")]
    detector: String,
    #[tabled(rename = "Title")]
    title: String,
    #[tabled(rename = "Severity")]
    severity: String,
}

#[derive(Tabled)]
struct TrendRow {
    #[tabled(rename = "Day")]
    day: String,
    #[tabled(rename = "Scans")]
    scans: usize,
    #[tabled(rename = "Findings")]
    findings: usize,
    #[tabled(rename = "Critical")]
    critical: usize,
    #[tabled(rename = "Mean risk")]
    mean_risk: String,
}

#[derive(Tabled)]
struct KbRow {
    #[tabled(rename = "SHA256 (12)")]
    sha256: String,
    #[tabled(rename = "Vendor")]
    vendor: String,
    #[tabled(rename = "Device")]
    device: String,
    #[tabled(rename = "Arch")]
    arch: String,
    #[tabled(rename = "Version")]
    version: String,
    #[tabled(rename = "Created")]
    created: String,
}

#[derive(Tabled)]
struct FeedRow {
    #[tabled(rename = "Feed")]
    name: String,
    #[tabled(rename = "IOCs")]
    iocs: usize,
    #[tabled(rename = "Version")]
    version: String,
    #[tabled(rename = "Updated")]
    updated: String,
}

#[derive(Tabled)]
struct AttackRow {
    #[tabled(rename = "Technique")]
    technique: String,
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Detectors")]
    detectors: String,
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("warn")
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(e) = run(cli) {
        eprintln!("{} {}", "error:".red().bold(), e);
        process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Scan(args) => cmd_scan(args),
        Commands::Baseline { command } => match command {
            BaselineCommands::Create(args) => cmd_baseline_create(args),
            BaselineCommands::Show(args) => cmd_baseline_show(args),
        },
        Commands::Report(args) => cmd_report(args),
        Commands::Validate(args) => cmd_validate(args),
        Commands::Detectors { command } => match command {
            DetectorCommands::List { json } => cmd_detectors_list(json),
            DetectorCommands::Info { name } => cmd_detectors_info(&name),
        },
        Commands::Info => cmd_info(),
        Commands::Fuzz(args) => cmd_fuzz(args),
        Commands::History { command } => cmd_history(command),
        Commands::Kb { command } => cmd_kb(command),
        Commands::Intel { command } => cmd_intel(command),
        Commands::Ml { command } => cmd_ml(command),
        Commands::Serve(args) => cmd_serve(args),
    }
}

// ─── Command Implementations ─────────────────────────────────────────────────

fn cmd_scan(args: ScanArgs) -> Result<()> {
    let baseline = match args.baseline {
        Some(ref path) => Some(Baseline::load(path)?),
        None => None,
    };

    let mut scanner = BarzakhScanner::new(baseline);

    // Register optional external detectors (declarative rules, intel
    // feeds, YARA rules, ML anomaly model).
    if let Some(rules_dir) = &args.rules_dir {
        let detector = barzakh_core::rules::RuleSetDetector::from_dir(rules_dir, "rules")
            .map_err(|e| anyhow::anyhow!("loading rules from {}: {e}", rules_dir.display()))?;
        scanner.register_detector(Box::new(detector));
        if !args.quiet && !args.json {
            println!("  {} rules loaded from {}", "+".cyan(), rules_dir.display());
        }
    }
    for feed in &args.ioc_feeds {
        let detector = barzakh_intel::ioc::IocFeedDetector::from_file(feed)
            .map_err(|e| anyhow::anyhow!("loading IOC feed {}: {e}", feed.display()))?;
        scanner.register_detector(Box::new(detector));
        if !args.quiet && !args.json {
            println!("  {} IOC feed loaded: {}", "+".cyan(), feed.display());
        }
    }
    if let Some(yara_path) = &args.yara {
        let detector = if yara_path.is_dir() {
            barzakh_intel::yara::YaraRuleDetector::from_dir(yara_path)
        } else {
            barzakh_intel::yara::YaraRuleDetector::from_file(yara_path)
        }
        .map_err(|e| anyhow::anyhow!("loading YARA rules {}: {e}", yara_path.display()))?;
        scanner.register_detector(Box::new(detector));
        if !args.quiet && !args.json {
            println!(
                "  {} YARA rules loaded: {}",
                "+".cyan(),
                yara_path.display()
            );
        }
    }
    if args.ml {
        scanner.register_detector(Box::new(barzakh_ml::iforest::MlAnomalyDetector::new()));
        if !args.quiet && !args.json {
            println!("  {} ML anomaly detector enabled", "+".cyan());
        }
    }

    let detector_count = scanner.detector_count();

    if !args.quiet && !args.json {
        println!(
            "{} {} {}",
            "▶".cyan().bold(),
            "Scanning".bold(),
            args.target.display()
        );
        println!("  {} detectors loaded", detector_count.to_string().cyan());
    }

    let pb = if !args.quiet && !args.json {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.cyan} {msg}")
                .unwrap(),
        );
        pb.set_message("Running detectors...");
        pb.enable_steady_tick(std::time::Duration::from_millis(100));
        Some(pb)
    } else {
        None
    };

    let scan_types: Option<Vec<String>> = args.scan_types;
    let scan_types_refs: Option<Vec<&str>> = scan_types
        .as_ref()
        .map(|v| v.iter().map(|s| s.as_str()).collect());

    let result = scanner.scan(&args.target, scan_types_refs.as_deref());

    if let Some(pb) = pb {
        pb.finish_and_clear();
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result.findings)?);
        if result.summary.bootkit_detected {
            process::exit(1);
        }
        return Ok(());
    }

    // Record into the history database (before exiting on detection).
    if let Some(history_db) = &args.history {
        let mut store = barzakh_store::history::ScanStore::open(history_db)?;
        let id = store.record(&result)?;
        if !args.quiet {
            println!(
                "  {} Scan #{} recorded in {}",
                "✓".green().bold(),
                id,
                history_db.display()
            );
        }
    }

    if !args.quiet {
        println!();
        println!(
            "{} Scan complete in {:.3}s",
            "✓".green().bold(),
            result.scan_info.duration_seconds
        );
        println!();

        if result.findings.is_empty() {
            println!("  {} No threats detected", "●".green());
        } else {
            let rows: Vec<FindingRow> = result
                .findings
                .iter()
                .map(|f| FindingRow {
                    severity: format_severity(&f.severity),
                    detector: f.detector.clone(),
                    title: f.title.clone(),
                })
                .collect();
            println!("{}", Table::new(&rows));
        }

        println!();
        println!("  {} {}", "Findings:".bold(), result.summary.total_findings);
        println!(
            "    {} {} {} {} {} {} {} {}",
            "Critical:".red().bold(),
            result.summary.critical_count,
            "High:".yellow().bold(),
            result.summary.high_count,
            "Medium:".bright_yellow(),
            result.summary.medium_count,
            "Low:".green(),
            result.summary.low_count,
        );

        if result.summary.bootkit_detected {
            println!();
            println!("  {} {}", "⚠".red().bold(), "BOOTKIT DETECTED".red().bold());
        }
    }

    if let Some(report_path) = args.report {
        let format = ReportFormat::from_str(&args.format)
            .ok_or_else(|| anyhow::anyhow!("Unknown format: {}", args.format))?;
        scanner.generate_report(&report_path, format)?;
        if !args.quiet {
            println!("  Report written to: {}", report_path.display());
        }
    }

    if result.summary.bootkit_detected {
        process::exit(1);
    }

    Ok(())
}

fn cmd_baseline_create(args: BaselineCreateArgs) -> Result<()> {
    println!(
        "{} Creating baseline from {}",
        "▶".cyan().bold(),
        args.target.display()
    );

    let image = std::fs::read(&args.target)
        .map_err(|e| anyhow::anyhow!("reading {}: {e}", args.target.display()))?;

    let read_capture = |path: &Option<PathBuf>, label: &str| -> Result<Option<String>> {
        match path {
            Some(p) => Ok(Some(std::fs::read_to_string(p).map_err(|e| {
                anyhow::anyhow!("reading {label} capture {}: {e}", p.display())
            })?)),
            None => Ok(None),
        }
    };
    let pcrs = read_capture(&args.pcrs, "PCR")?;
    let memmap = read_capture(&args.memmap, "memory-map")?;
    let eventlog = read_capture(&args.eventlog, "event-log")?;

    let baseline = Baseline::capture(
        &image,
        pcrs.as_deref(),
        memmap.as_deref(),
        eventlog.as_deref(),
        &args.target.display().to_string(),
    );

    std::fs::write(&args.output, serde_json::to_string_pretty(&baseline)?)?;
    println!(
        "{} Baseline written to: {} ({})",
        "✓".green().bold(),
        args.output.display(),
        if baseline.is_populated() {
            "real capture data".green().to_string()
        } else {
            "image hash only".yellow().to_string()
        }
    );

    Ok(())
}

fn cmd_baseline_show(args: BaselineShowArgs) -> Result<()> {
    let baseline = Baseline::load(&args.path)?;
    println!("{} Baseline: {}", "▶".cyan().bold(), args.path.display());
    println!("{}", serde_json::to_string_pretty(&baseline)?);
    Ok(())
}

fn cmd_report(args: ReportArgs) -> Result<()> {
    let baseline = match args.baseline {
        Some(ref path) => Some(Baseline::load(path)?),
        None => None,
    };

    let mut scanner = BarzakhScanner::new(baseline);

    println!(
        "{} Scanning {} for report...",
        "▶".cyan().bold(),
        args.target.display()
    );

    scanner.scan(&args.target, None);

    let format = ReportFormat::from_str(&args.format)
        .ok_or_else(|| anyhow::anyhow!("Unknown format: {}", args.format))?;

    scanner.generate_report(&args.output, format)?;
    println!(
        "{} Report written to: {}",
        "✓".green().bold(),
        args.output.display()
    );

    Ok(())
}

fn cmd_validate(args: ValidateArgs) -> Result<()> {
    let baseline = match args.baseline {
        Some(ref path) => Some(Baseline::load(path)?),
        None => None,
    };

    let scanner = BarzakhScanner::new(baseline);

    if !args.json {
        println!(
            "{} Validating against corpus: {}",
            "▶".cyan().bold(),
            args.corpus.display()
        );
    }

    let metrics = scanner.validate_against_corpus(&args.corpus)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&metrics)?);
    } else {
        println!();
        println!("  {}", "Validation Results".bold());
        println!("  ─────────────────────────────");
        println!(
            "  True Positives:  {}",
            metrics.true_positives.to_string().green()
        );
        println!(
            "  False Positives: {}",
            metrics.false_positives.to_string().red()
        );
        println!(
            "  True Negatives:  {}",
            metrics.true_negatives.to_string().green()
        );
        println!(
            "  False Negatives: {}",
            metrics.false_negatives.to_string().red()
        );
        println!("  ─────────────────────────────");
        println!(
            "  TPR: {}",
            format!("{:.4}", metrics.true_positive_rate).cyan().bold()
        );
        println!(
            "  FPR: {}",
            format!("{:.4}", metrics.false_positive_rate).cyan().bold()
        );
    }

    Ok(())
}

fn cmd_detectors_list(json: bool) -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);

    if json {
        let names: Vec<&str> = detectors.iter().map(|d| d.name()).collect();
        println!("{}", serde_json::to_string_pretty(&names)?);
        return Ok(());
    }

    let rows: Vec<DetectorRow> = detectors
        .iter()
        .enumerate()
        .map(|(i, d)| DetectorRow {
            index: i + 1,
            name: d.name().to_string(),
        })
        .collect();

    println!(
        "{} {} security detectors available:\n",
        "▶".cyan().bold(),
        detectors.len().to_string().yellow()
    );
    println!("{}", Table::new(&rows));
    Ok(())
}

fn cmd_detectors_info(name: &str) -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);

    let detector = detectors.iter().find(|d| d.name() == name).ok_or_else(|| {
        anyhow::anyhow!(
            "Unknown detector '{}'. Use 'barzakh detectors list' to see available detectors.",
            name
        )
    })?;

    println!("{} {}", "Detector:".bold(), detector.name().cyan());
    Ok(())
}

fn cmd_info() -> Result<()> {
    let detectors = barzakh_core::detectors::create_all_detectors(None);

    println!();
    println!("  {}", "Barzakh — UEFI Firmware Security Scanner".bold());
    println!("  ═══════════════════════════════════════════");
    println!();
    println!("  Version:       {}", env!("CARGO_PKG_VERSION").cyan());
    println!("  Detectors:     {}", detectors.len().to_string().yellow());
    println!("  Architectures: x86_64, aarch64, riscv64");
    println!("  Report formats: JSON, HTML, Markdown");
    println!();
    println!("  {}", "Detector Categories:".bold());
    println!("    • TPM/PCR analysis (PCR, PCR Oracle, PCR Replay, Attestation)");
    println!("    • Memory forensics (Memory, Hook, Runtime Hook, SMM)");
    println!("    • Firmware structure (Firmware Volume, SPI Integrity, MBR)");
    println!("    • Secure Boot chain (SecureBoot, SecureBoot Chain, Differ)");
    println!("    • Behavioral analysis (Entropy, Self-Erasure, Time Travel)");
    println!("    • Intel ME/Ring -3 (HECI, ME SPI, AMT, fTPM, ME DMA)");
    println!("    • Ring -4/Microarch (Microcode, Spectre, Thermal, Voltage, Debug, Rowhammer)");
    println!();

    Ok(())
}

fn cmd_fuzz(args: FuzzArgs) -> Result<()> {
    use barzakh_adversary::harness::{FuzzHarness, HarnessConfig};

    // Protocol-aware fuzzing: mutate structurally-valid seeds of a given
    // boot-time protocol and measure which detectors fire per mutation.
    if let Some(protocol_name) = &args.protocol {
        let protocol = barzakh_core::fuzz::Protocol::parse(protocol_name).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown protocol '{protocol_name}' (dhcpv6, bmp, capsule, httpboot, tcg, hii)"
            )
        })?;

        if !args.json {
            println!(
                "{} Protocol-aware fuzzing: {} ({} iterations)",
                "▶".cyan().bold(),
                protocol.name(),
                args.iterations
            );
        }

        let mut scanner = BarzakhScanner::new(None);
        let mut fuzzer = barzakh_core::fuzz::ProtocolFuzzer::new(protocol, 0xFEED_FACE);
        let stats = fuzzer.run(args.iterations as usize, |input| {
            let dir = std::env::temp_dir().join(format!("barzakh-fuzz-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            let path = dir.join("input.bin");
            let _ = std::fs::write(&path, input);
            let result = scanner.scan(&path, None);
            let _ = std::fs::remove_file(&path);
            result
                .findings
                .iter()
                .map(|f| f.detector.clone())
                .collect::<Vec<String>>()
        });

        if args.json {
            println!("{}", serde_json::to_string_pretty(&stats)?);
        } else {
            println!(
                "{} Fuzzing complete: {}/{} mutated inputs detected",
                "✓".green().bold(),
                stats.detected_mutations,
                stats.detected_mutations + stats.undetected_mutations
            );
        }
        return Ok(());
    }

    let config = HarnessConfig {
        iterations: args.iterations,
        output_dir: args.output_dir.clone(),
        mutate: args.mutate,
        parallel: true,
    };

    if !args.json {
        println!(
            "{} Running fuzzing harness ({} iterations, mutate={})",
            "▶".cyan().bold(),
            args.iterations,
            args.mutate
        );
        println!("  Output dir: {}", args.output_dir.display());
    }

    let harness = FuzzHarness::new(config);
    let result = harness.run()?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!();
        println!(
            "{} Fuzzing complete in {:.2}s",
            "✓".green().bold(),
            result.duration_secs
        );
        println!("  Total runs:  {}", result.total_runs.to_string().cyan());
        println!(
            "  Coverage:    {}",
            format!("{:.1}%", result.gap_report.coverage_pct).green()
        );
        println!(
            "  Gaps found:  {}",
            result.gap_report.total_gaps.to_string().yellow()
        );

        if !result.gap_report.entries.is_empty() {
            println!();
            println!("  {}", "Detection Gaps:".bold());
            for gap in &result.gap_report.entries {
                println!(
                    "    {} {} → missed: {}",
                    "•".red(),
                    gap.payload_name,
                    gap.missed_detectors.join(", ")
                );
            }
        }

        if !result.gap_report.undetected_categories.is_empty() {
            println!();
            println!("  {}", "Undetected categories:".bold());
            for cat in &result.gap_report.undetected_categories {
                println!("    {} {}", "○".yellow(), cat);
            }
        }
    }

    Ok(())
}

// ─── History ─────────────────────────────────────────────────────────────────

fn cmd_history(command: HistoryCommands) -> Result<()> {
    use barzakh_store::history::ScanStore;

    match command {
        HistoryCommands::List { db, limit } => {
            let store = ScanStore::open(&db)?;
            let records = store.list(limit)?;
            if records.is_empty() {
                println!("{} No scans recorded in {}", "○".yellow(), db.display());
                return Ok(());
            }
            let rows: Vec<HistoryRow> = records
                .iter()
                .map(|r| HistoryRow {
                    id: r.id,
                    timestamp: r
                        .timestamp
                        .split('T')
                        .next()
                        .unwrap_or(&r.timestamp)
                        .to_string(),
                    target: short_path(&r.target),
                    risk: format!("{} ({})", r.risk_level, r.risk_score),
                    verdict: if r.bootkit_detected {
                        "BOOTKIT".to_string()
                    } else {
                        "clean".to_string()
                    },
                    findings: format!(
                        "{}/{}/{}/{}/{}",
                        r.critical_count, r.high_count, r.medium_count, r.low_count, r.info_count
                    ),
                })
                .collect();
            println!("{} Scan history ({}):\n", "▶".cyan().bold(), db.display());
            println!("{}", Table::new(&rows));
        }
        HistoryCommands::Show { id, db } => {
            let store = ScanStore::open(&db)?;
            let record = store.get(id)?;
            let findings = store.get_findings(id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "record": record,
                    "findings": findings,
                }))?
            );
        }
        HistoryCommands::Diff { a, b, db } => {
            let store = ScanStore::open(&db)?;
            let diff = store.diff(a, b)?;
            if diff.is_empty() {
                println!(
                    "{} No differences between scans #{a} and #{b}",
                    "○".yellow()
                );
                return Ok(());
            }
            let rows: Vec<DiffRow> = diff
                .iter()
                .map(|d| DiffRow {
                    status: if d.status == "new" {
                        "new".red().to_string()
                    } else {
                        "resolved".green().to_string()
                    },
                    detector: d.detector.clone(),
                    title: d.title.clone(),
                    severity: d.severity.clone(),
                })
                .collect();
            println!("{} Diff #{a} → #{b}:\n", "▶".cyan().bold());
            println!("{}", Table::new(&rows));
        }
        HistoryCommands::Trends { db } => {
            let store = ScanStore::open(&db)?;
            let trends = store.trends()?;
            if trends.is_empty() {
                println!("{} No scans recorded in {}", "○".yellow(), db.display());
                return Ok(());
            }
            let rows: Vec<TrendRow> = trends
                .iter()
                .map(|t| TrendRow {
                    day: t.day.clone(),
                    scans: t.scans,
                    findings: t.total_findings,
                    critical: t.critical_findings,
                    mean_risk: format!("{:.1}", t.mean_risk),
                })
                .collect();
            println!("{} Daily trends ({}):\n", "▶".cyan().bold(), db.display());
            println!("{}", Table::new(&rows));
        }
    }
    Ok(())
}

// ─── Knowledge base ──────────────────────────────────────────────────────────

fn cmd_kb(command: KbCommands) -> Result<()> {
    use barzakh_store::kb::{FirmwareProfile, KnowledgeBase};

    match command {
        KbCommands::Add {
            target,
            vendor,
            device,
            family,
            fw_version,
            arch,
            notes,
            known_clean,
            db,
        } => {
            let image = std::fs::read(&target)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", target.display()))?;
            let mut profile = FirmwareProfile::from_image(&image);
            profile.vendor = vendor.unwrap_or_default();
            profile.device = device.unwrap_or_default();
            profile.family = family;
            profile.version = fw_version;
            profile.arch = arch;
            profile.notes = notes;
            profile.known_clean = known_clean;

            let kb = KnowledgeBase::open(&db)?;
            kb.upsert(&profile)?;

            println!("{} Profile recorded:", "✓".green().bold());
            println!("  sha256:     {}", profile.sha256);
            println!("  size:       {}", profile.size);
            println!("  vendor:     {}", profile.vendor);
            println!("  device:     {}", profile.device);
            println!("  known-clean: {}", profile.known_clean);
            println!("  kb:         {}", db.display());
        }
        KbCommands::List { db } => {
            let kb = KnowledgeBase::open(&db)?;
            let profiles = kb.list()?;
            if profiles.is_empty() {
                println!(
                    "{} Knowledge base is empty ({})",
                    "○".yellow(),
                    db.display()
                );
                return Ok(());
            }
            let rows: Vec<KbRow> = profiles
                .iter()
                .map(|p| KbRow {
                    sha256: p.sha256.chars().take(12).collect(),
                    vendor: p.vendor.clone(),
                    device: p.device.clone(),
                    arch: p.arch.clone().unwrap_or_default(),
                    version: p.version.clone().unwrap_or_default(),
                    created: p
                        .created
                        .as_deref()
                        .unwrap_or("")
                        .split('T')
                        .next()
                        .unwrap_or("")
                        .to_string(),
                })
                .collect();
            println!(
                "{} Firmware knowledge base ({}):\n",
                "▶".cyan().bold(),
                db.display()
            );
            println!("{}", Table::new(&rows));
        }
        KbCommands::Search { query, db } => {
            let kb = KnowledgeBase::open(&db)?;
            let profiles = kb.search(&query)?;
            if profiles.is_empty() {
                println!("{} No profiles match '{query}'", "○".yellow());
                return Ok(());
            }
            let rows: Vec<KbRow> = profiles
                .iter()
                .map(|p| KbRow {
                    sha256: p.sha256.chars().take(12).collect(),
                    vendor: p.vendor.clone(),
                    device: p.device.clone(),
                    arch: p.arch.clone().unwrap_or_default(),
                    version: p.version.clone().unwrap_or_default(),
                    created: p
                        .created
                        .as_deref()
                        .unwrap_or("")
                        .split('T')
                        .next()
                        .unwrap_or("")
                        .to_string(),
                })
                .collect();
            println!("{} Matches for '{query}':\n", "▶".cyan().bold());
            println!("{}", Table::new(&rows));
        }
        KbCommands::Export {
            output,
            anonymize,
            db,
        } => {
            let kb = KnowledgeBase::open(&db)?;
            kb.export(&output, anonymize)?;
            println!(
                "{} Exported knowledge base to {} ({})",
                "✓".green().bold(),
                output.display(),
                if anonymize {
                    "anonymized".cyan()
                } else {
                    "full detail".yellow()
                }
            );
        }
        KbCommands::Import { input, db } => {
            let kb = KnowledgeBase::open(&db)?;
            let count = kb.import(&input)?;
            println!(
                "{} Imported {count} profiles from {}",
                "✓".green().bold(),
                input.display()
            );
        }
    }
    Ok(())
}

// ─── Intel ───────────────────────────────────────────────────────────────────

fn cmd_intel(command: IntelCommands) -> Result<()> {
    match command {
        IntelCommands::Feeds { dir } => {
            let mut entries = Vec::new();
            for entry in std::fs::read_dir(&dir)
                .map_err(|e| anyhow::anyhow!("reading {}: {e}", dir.display()))?
            {
                let path = entry?.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                match barzakh_intel::ioc::IocFeed::load(&path) {
                    Ok(feed) => entries.push(FeedRow {
                        name: feed.name.clone(),
                        iocs: feed.iocs.len(),
                        version: feed.version.to_string(),
                        updated: feed.updated.clone().unwrap_or_else(|| "-".to_string()),
                    }),
                    Err(e) => eprintln!("{} invalid feed {}: {e}", "✗".red(), path.display()),
                }
            }
            if entries.is_empty() {
                println!("{} No IOC feeds found in {}", "○".yellow(), dir.display());
                return Ok(());
            }
            println!("{} IOC feeds in {}:\n", "▶".cyan().bold(), dir.display());
            println!("{}", Table::new(&entries));
        }
        IntelCommands::Misp {
            target,
            output,
            title,
        } => {
            let mut scanner = BarzakhScanner::new(None);
            let result = scanner.scan(&target, None);
            let event = barzakh_intel::misp::render_misp_event(&result, title.as_deref());
            std::fs::write(&output, serde_json::to_string_pretty(&event)?)?;
            println!(
                "{} MISP event written to {} ({} findings)",
                "✓".green().bold(),
                output.display(),
                result.summary.total_findings
            );
        }
        IntelCommands::Attack { target } => {
            let mut scanner = BarzakhScanner::new(None);
            let result = scanner.scan(&target, None);
            let map = barzakh_intel::attack::map_findings(&result.findings);

            if map.techniques.is_empty() {
                println!("{} No ATT&CK mappings (no findings)", "○".yellow());
                return Ok(());
            }

            println!(
                "{} MITRE ATT&CK mapping for {}:\n",
                "▶".cyan().bold(),
                target.display()
            );
            let rows: Vec<AttackRow> = map
                .techniques
                .iter()
                .map(|t| {
                    let detectors: Vec<String> = map
                        .by_detector
                        .iter()
                        .filter(|dm| dm.techniques.iter().any(|x| x.id == t.id))
                        .map(|dm| dm.detector.clone())
                        .collect();
                    AttackRow {
                        technique: t.id.to_string(),
                        name: t.name.to_string(),
                        detectors: detectors.join(", "),
                    }
                })
                .collect();
            println!("{}", Table::new(&rows));
        }
    }
    Ok(())
}

// ─── ML ──────────────────────────────────────────────────────────────────────

fn cmd_ml(command: MlCommands) -> Result<()> {
    use barzakh_ml::train::TrainedModel;

    match command {
        MlCommands::Train { corpus, output } => {
            println!(
                "{} Training on corpus {}",
                "▶".cyan().bold(),
                corpus.display()
            );
            let model = TrainedModel::train_from_corpus(&corpus)?;
            model.save(&output)?;
            println!(
                "{} Model trained: {} samples ({} malicious / {} clean), written to {}",
                "✓".green().bold(),
                model.corpus_stats.samples,
                model.corpus_stats.malicious,
                model.corpus_stats.benign,
                output.display()
            );
        }
        MlCommands::Evaluate { corpus, model } => {
            let model = TrainedModel::load(&model)?;
            let report = model.evaluate_corpus(&corpus)?;

            println!("{} Evaluation on {}:", "▶".cyan().bold(), corpus.display());
            println!(
                "  Corpus:        {} samples ({} malicious, {} clean)",
                report.samples, report.malicious, report.benign
            );
            println!(
                "  Isolation forest:   TPR {:.2}  FPR {:.2}",
                report.iforest_tpr, report.iforest_fpr
            );
            println!(
                "  Logistic regression: TPR {:.2}  FPR {:.2}",
                report.classifier_tpr, report.classifier_fpr
            );
            println!("  Confusion matrix (classifier):");
            println!("                predicted malicious  predicted benign");
            println!(
                "  actual malicious      {:>18}  {:>16}",
                report.confusion[0][0], report.confusion[0][1]
            );
            println!(
                "  actual benign         {:>18}  {:>16}",
                report.confusion[1][0], report.confusion[1][1]
            );
        }
    }
    Ok(())
}

// ─── Serve ───────────────────────────────────────────────────────────────────

fn cmd_serve(args: ServeArgs) -> Result<()> {
    let config = barzakh_server::ServerConfig {
        port: args.port,
        db_path: args.db,
    };
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(barzakh_server::run_server(config))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Compact a filesystem path for table display (keep last 2 components).
fn short_path(path: &str) -> String {
    let components: Vec<&str> = path
        .rsplit('/')
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    if components.len() == 2 {
        format!("…/{}", components[1])
    } else {
        components.first().unwrap_or(&path).to_string()
    }
}

fn format_severity(severity: &Severity) -> String {
    match severity {
        Severity::Critical => "CRIT".red().bold().to_string(),
        Severity::High => "HIGH".yellow().bold().to_string(),
        Severity::Medium => "MED".bright_yellow().to_string(),
        Severity::Low => "LOW".green().to_string(),
        Severity::Info => "INFO".blue().to_string(),
    }
}
