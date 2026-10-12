use std::path::PathBuf;
use std::process;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;
use tabled::{Table, Tabled};
use tracing_subscriber::EnvFilter;

use barzakh_adversary::deploy::esp_image::EspImageBuilder;
use barzakh_adversary::deploy::qemu::{self, QemuConfig};
use barzakh_adversary::validate::runner::validate_all;
use barzakh_adversary::{create_all_payloads, Arch, PayloadConfig};

#[derive(Parser)]
#[command(
    name = "barzakh-adversary",
    about = "Barzakh — UEFI Red-Team Payload Toolkit",
    long_about = "Generate UEFI bootkit payloads for red-team engagements, build ESP images,\n\
                  and validate evasion against detection engines.",
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
    /// Generate a specific adversary payload
    Generate(GenerateArgs),

    /// List all available adversary payloads
    List,

    /// Generate a full test corpus (malicious + clean pairs)
    Corpus(CorpusArgs),

    /// Validate payloads against the scanner
    Validate(ValidateArgs),

    /// QEMU firmware emulation integration
    Qemu {
        #[command(subcommand)]
        command: QemuCommands,
    },

    /// Build EFI System Partition images
    Esp {
        #[command(subcommand)]
        command: EspCommands,
    },

    /// Inject a single payload into an existing firmware image
    InjectSingle(InjectSingleArgs),
}

// ─── Generate ───────────────────────────────────────────────────────────────

#[derive(Parser)]
struct GenerateArgs {
    /// Payload name (use 'list' to see available)
    #[arg(short, long)]
    payload: String,

    /// Output path for generated binary
    #[arg(short, long)]
    output: PathBuf,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: ArchArg,

    /// Image size in bytes
    #[arg(short, long, default_value = "65536")]
    size: usize,
}

// ─── Corpus ─────────────────────────────────────────────────────────────────

#[derive(Parser)]
struct CorpusArgs {
    /// Output directory for corpus files
    #[arg(short, long, default_value = "corpus")]
    output: PathBuf,
}

// ─── Validate ───────────────────────────────────────────────────────────────

#[derive(Parser)]
struct ValidateArgs {
    /// Directory containing generated corpus dumps
    #[arg(short, long)]
    corpus: PathBuf,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

// ─── QEMU ───────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum QemuCommands {
    /// Show QEMU launch configuration for a firmware image
    Run(QemuRunArgs),

    /// Dump memory from a QEMU instance
    Dump(QemuDumpArgs),
}

#[derive(Parser)]
struct QemuRunArgs {
    /// ESP disk image to boot
    #[arg(short, long)]
    esp: PathBuf,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: ArchArg,

    /// OVMF/firmware path
    #[arg(short, long)]
    firmware: Option<String>,

    /// VM memory in MB
    #[arg(short, long, default_value = "256")]
    memory: u32,

    /// Timeout in seconds
    #[arg(short, long, default_value = "30")]
    timeout: u32,
}

#[derive(Parser)]
struct QemuDumpArgs {
    /// Output path for memory dump
    #[arg(short, long)]
    output: PathBuf,

    /// Target architecture
    #[arg(short, long, value_enum, default_value = "x86-64")]
    arch: ArchArg,
}

// ─── ESP ────────────────────────────────────────────────────────────────────

#[derive(Subcommand)]
enum EspCommands {
    /// Build an ESP image with an embedded payload
    Build(EspBuildArgs),
}

#[derive(Parser)]
struct EspBuildArgs {
    /// Path to payload binary to embed
    #[arg(short, long)]
    payload: PathBuf,

    /// Output ESP image path
    #[arg(short, long, default_value = "esp.img")]
    output: PathBuf,

    /// ESP image size in MB
    #[arg(short, long, default_value = "64")]
    size: u32,
}

// ─── InjectSingle ──────────────────────────────────────────────────────────

#[derive(Parser)]
struct InjectSingleArgs {
    /// Input firmware image to inject into
    #[arg(long)]
    input: PathBuf,

    /// Output path for the modified firmware image
    #[arg(long)]
    output: PathBuf,

    /// Payload name to inject (use 'list' to see available)
    #[arg(long)]
    payload: String,

    /// Target architecture
    #[arg(long, value_enum, default_value = "x86-64")]
    arch: ArchArg,

    /// Payload generation size in bytes (defaults to input file size)
    #[arg(long)]
    size: Option<usize>,
}

// ─── Shared types ───────────────────────────────────────────────────────────

#[derive(Clone, ValueEnum)]
enum ArchArg {
    #[value(name = "x86-64")]
    X86_64,
    #[value(name = "aarch64")]
    Aarch64,
    #[value(name = "riscv64")]
    RiscV64,
}

impl From<ArchArg> for Arch {
    fn from(a: ArchArg) -> Self {
        match a {
            ArchArg::X86_64 => Arch::X86_64,
            ArchArg::Aarch64 => Arch::Aarch64,
            ArchArg::RiscV64 => Arch::RiscV64,
        }
    }
}

#[derive(Tabled)]
struct PayloadRow {
    #[tabled(rename = "#")]
    index: usize,
    #[tabled(rename = "Payload")]
    name: String,
    #[tabled(rename = "Arch")]
    arch: String,
    #[tabled(rename = "Expected Detections")]
    detections: usize,
}

#[derive(Tabled)]
struct ValidationRow {
    #[tabled(rename = "Payload")]
    name: String,
    #[tabled(rename = "Detected")]
    detected: String,
    #[tabled(rename = "Expected")]
    expected: usize,
    #[tabled(rename = "Matched")]
    matched: usize,
}

// ─── Main ───────────────────────────────────────────────────────────────────

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
        Commands::Generate(args) => cmd_generate(args),
        Commands::List => cmd_list(),
        Commands::Corpus(args) => cmd_corpus(args),
        Commands::Validate(args) => cmd_validate(args),
        Commands::Qemu { command } => match command {
            QemuCommands::Run(args) => cmd_qemu_run(args),
            QemuCommands::Dump(args) => cmd_qemu_dump(args),
        },
        Commands::Esp { command } => match command {
            EspCommands::Build(args) => cmd_esp_build(args),
        },
        Commands::InjectSingle(args) => cmd_inject_single(args),
    }
}

// ─── Command Implementations ────────────────────────────────────────────────

fn cmd_generate(args: GenerateArgs) -> Result<()> {
    let payloads = create_all_payloads();
    let payload = payloads
        .iter()
        .find(|p| p.name() == args.payload)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown payload '{}'. Use 'barzakh-adversary list' to see available payloads.",
                args.payload
            )
        })?;

    let config = PayloadConfig {
        arch: args.arch.into(),
        size: args.size,
    };

    println!(
        "{} Generating payload: {}",
        "▶".cyan().bold(),
        payload.name().yellow()
    );

    let data = payload.generate(&config)?;
    std::fs::write(&args.output, &data)?;

    println!(
        "{} Written {} bytes to {}",
        "✓".green().bold(),
        data.len(),
        args.output.display()
    );

    Ok(())
}

fn cmd_list() -> Result<()> {
    let payloads = create_all_payloads();

    let rows: Vec<PayloadRow> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| PayloadRow {
            index: i + 1,
            name: p.name().to_string(),
            arch: format!("{:?}", p.arch()),
            detections: p.expected_detections().len(),
        })
        .collect();

    println!(
        "{} {} adversary payloads available:\n",
        "▶".cyan().bold(),
        payloads.len().to_string().yellow()
    );
    println!("{}", Table::new(&rows));
    Ok(())
}

fn cmd_corpus(args: CorpusArgs) -> Result<()> {
    println!(
        "{} Generating test corpus to {}",
        "▶".cyan().bold(),
        args.output.display()
    );

    let generated = barzakh_adversary::corpus::generate_corpus(&args.output)?;

    println!(
        "{} Generated {} files",
        "✓".green().bold(),
        generated.len().to_string().yellow()
    );

    for name in &generated {
        let icon = if name.starts_with("malicious_") {
            "⚡".red()
        } else {
            "○".green()
        };
        println!("  {} {}", icon, name);
    }

    Ok(())
}

fn cmd_validate(args: ValidateArgs) -> Result<()> {
    let payloads = create_all_payloads();

    if !args.json {
        println!(
            "{} Validating {} payloads against scanner...",
            "▶".cyan().bold(),
            payloads.len()
        );
    }

    let report = validate_all(&payloads, &args.corpus)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let rows: Vec<ValidationRow> = report
        .results
        .iter()
        .map(|r| ValidationRow {
            name: r.payload_name.clone(),
            detected: if r.detected {
                "YES".green().to_string()
            } else {
                "NO".red().to_string()
            },
            expected: r.expected_findings,
            matched: r.matched_findings,
        })
        .collect();

    println!();
    println!("{}", Table::new(&rows));
    println!();
    println!("  {}", "Summary".bold());
    println!("  ─────────────────────────────");
    println!("  Total payloads: {}", report.total_payloads);
    println!(
        "  Detected:       {}",
        report.detected_count.to_string().green()
    );
    println!(
        "  Missed:         {}",
        report.missed_count.to_string().red()
    );
    println!(
        "  TPR:            {}",
        format!("{:.2}%", report.true_positive_rate * 100.0)
            .cyan()
            .bold()
    );
    println!(
        "  FPR:            {}",
        format!("{:.2}%", report.false_positive_rate * 100.0)
            .cyan()
            .bold()
    );
    println!(
        "  Clean scanned:  {} ({} FP, {} TN)",
        report.false_positives + report.true_negatives,
        report.false_positives,
        report.true_negatives,
    );

    Ok(())
}

fn cmd_qemu_run(args: QemuRunArgs) -> Result<()> {
    let config = QemuConfig {
        arch: args.arch.into(),
        memory_mb: args.memory,
        firmware_path: args.firmware,
        timeout_secs: args.timeout,
    };

    let qemu_args = config.build_args(&args.esp);

    println!("{} QEMU Launch Configuration", "▶".cyan().bold());
    println!("  Binary:   {}", config.binary_name().yellow());
    println!("  Arch:     {:?}", config.arch);
    println!("  Memory:   {}MB", config.memory_mb);
    println!("  Timeout:  {}s", config.timeout_secs);
    println!("  ESP:      {}", args.esp.display());
    println!();
    println!("  {}", "Command:".bold());
    println!("  {} {}", config.binary_name(), qemu_args.join(" "));

    Ok(())
}

fn cmd_qemu_dump(args: QemuDumpArgs) -> Result<()> {
    let config = QemuConfig {
        arch: args.arch.into(),
        ..QemuConfig::default()
    };

    qemu::dump_memory(&config, &args.output)?;
    Ok(())
}

fn cmd_esp_build(args: EspBuildArgs) -> Result<()> {
    println!("{} Building ESP image ({}MB)", "▶".cyan().bold(), args.size);

    let payload_data = std::fs::read(&args.payload)?;
    let builder = EspImageBuilder::new(args.size);
    builder.build_with_payload(&payload_data, &args.output)?;

    println!(
        "{} ESP image written to: {}",
        "✓".green().bold(),
        args.output.display()
    );
    println!(
        "  Payload: {} ({} bytes)",
        args.payload.display(),
        payload_data.len()
    );

    Ok(())
}

fn cmd_inject_single(args: InjectSingleArgs) -> Result<()> {
    let payloads = create_all_payloads();
    let payload = payloads
        .iter()
        .find(|p| p.name() == args.payload)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Unknown payload '{}'. Use 'barzakh-adversary list' to see available payloads.",
                args.payload
            )
        })?;

    // Read the original firmware image
    let input_data = std::fs::read(&args.input)?;

    let size = args.size.unwrap_or(input_data.len().max(0x10000));
    let config = PayloadConfig {
        arch: args.arch.into(),
        size,
    };

    println!(
        "{} Generating payload: {}",
        "▶".cyan().bold(),
        payload.name().yellow()
    );

    let payload_data = payload.generate(&config)?;

    // Overlay: write payload bytes at offset 0, keep rest of input intact.
    // Output length = max(input length, payload length).
    let output_len = input_data.len().max(payload_data.len());
    let mut output_data = vec![0u8; output_len];

    // Copy input as the base
    output_data[..input_data.len()].copy_from_slice(&input_data);
    // Overlay payload at offset 0
    output_data[..payload_data.len()].copy_from_slice(&payload_data);

    std::fs::write(&args.output, &output_data)?;

    println!(
        "{} Injected '{}' ({} bytes) into {} ({} bytes) → {} ({} bytes)",
        "✓".green().bold(),
        payload.name().yellow(),
        payload_data.len(),
        args.input.display(),
        input_data.len(),
        args.output.display(),
        output_data.len(),
    );

    let expected = payload.expected_detections();
    if !expected.is_empty() {
        println!("  Expected detections:");
        for exp in &expected {
            println!("    - {} (>= {:?})", exp.detector, exp.min_severity);
        }
    }

    Ok(())
}
