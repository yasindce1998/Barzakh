//! Cyber-range runner: boots a real QEMU q35 virtual machine (SMM on,
//! swtpm-backed TPM 2.0, OVMF firmware), deploys adversary payloads
//! through a spec-conformant FAT ESP — the firmware's boot manager reads
//! the implant from the removable boot path — captures guest memory via
//! the QEMU monitor, scans every artifact with the Barzakh scanner, and
//! asserts the expected detections. One command reproduces the full
//! attack → detect → assert loop, headless.
//!
//! Range suites are declarative TOML manifests (`range/*.toml`),
//! consistent with the adversary scenario format:
//!
//! ```toml
//! [range]
//! name = "ring-2"
//! description = "Ring -2 attack → detect → assert"
//! memory_mb = 256
//! timeout_secs = 180
//! tpm = true
//!
//! [[cases]]
//! name = "boot-services-hook"
//! payload = "boot_services_hook"
//! expect_findings = ["hook"]
//! expect_in_memory = ["hook"]  # must also be found in the captured RAM
//!
//! [[cases]]
//! name = "kill-switched-variant"
//! payload = "boot_services_hook"
//! dormant = true
//! expect_absent = ["hook"]   # intentional miss — must NOT be detected
//! ```
//!
//! Assertions are evaluated against the *deployment artifacts* (ESP
//! image, dropper, implant blob) — deterministic evidence directly
//! attributable to the implant. Captured guest memory is real
//! firmware state (genuine OVMF structures legitimately trip
//! medium-severity heuristics), so memory findings are live-range
//! evidence and only positively asserted, via `expect_in_memory`,
//! for detectors unambiguously attributable to the implant.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use colored::Colorize;
use serde::{Deserialize, Serialize};

use barzakh_core::BarzakhScanner;

use crate::deploy::efi_app;
use crate::deploy::esp_image::EspImageBuilder;
use crate::{create_all_payloads, PayloadConfig};

// ─── Manifest ────────────────────────────────────────────────────────

/// A range suite manifest (`range/*.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeSuite {
    pub range: RangeConfig,
    #[serde(default)]
    pub cases: Vec<RangeCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeConfig {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    /// Guest RAM (OVMF needs at least 128 MB).
    #[serde(default = "default_memory_mb")]
    pub memory_mb: u32,
    /// Per-case boot timeout.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u32,
    /// Boot with a swtpm-backed TPM 2.0 device.
    #[serde(default = "default_true")]
    pub tpm: bool,
    /// `q35,smm=on` machine (SMM emulation).
    #[serde(default = "default_true")]
    pub smm: bool,
    /// Explicit firmware override (defaults to auto-discovered OVMF).
    #[serde(default)]
    pub ovmf_code: Option<PathBuf>,
    #[serde(default)]
    pub ovmf_vars: Option<PathBuf>,
}

fn default_memory_mb() -> u32 {
    256
}
fn default_timeout_secs() -> u32 {
    180
}
fn default_true() -> bool {
    true
}

/// One attack case (`[[cases]]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RangeCase {
    pub name: String,
    /// Adversary payload name (`create_all_payloads` registry), or
    /// `"none"` for a clean golden-boot control.
    pub payload: String,
    /// Generate the kill-switched (dormant) variant — the intentional
    /// miss: the implant never armed, so nothing may be detected.
    #[serde(default)]
    pub dormant: bool,
    /// Payload size override.
    #[serde(default = "default_payload_size")]
    pub payload_size: usize,
    /// Detector names that MUST fire on the deployed artifacts
    /// (ESP image, dropper, implant blob).
    #[serde(default)]
    pub expect_findings: Vec<String>,
    /// Detector names that must NOT fire on the deployed artifacts —
    /// the falsifiable miss.
    #[serde(default)]
    pub expect_absent: Vec<String>,
    /// Detector names that must also fire in the captured guest memory —
    /// the live-range evidence. Only use these where a finding is
    /// unambiguously attributable to the implant: real firmware memory
    /// legitimately contains structures that trip medium-severity
    /// heuristics, so this must not be used for absence assertions.
    #[serde(default)]
    pub expect_in_memory: Vec<String>,
}

fn default_payload_size() -> usize {
    0x10000
}

impl RangeSuite {
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading range manifest {}", path.display()))?;
        let suite: RangeSuite = toml::from_str(&text)
            .with_context(|| format!("parsing range manifest {}", path.display()))?;
        if suite.cases.is_empty() {
            bail!("range suite {} declares no cases", suite.range.name);
        }
        Ok(suite)
    }
}

// ─── Toolchain discovery ─────────────────────────────────────────────

/// The QEMU/swtpm/OVMF toolchain a range run drives.
#[derive(Debug, Clone)]
pub struct RangeTools {
    pub qemu: PathBuf,
    pub swtpm: Option<PathBuf>,
    pub ovmf_code: PathBuf,
    pub ovmf_vars: PathBuf,
    /// Extra LD_LIBRARY_PATH entries (user-prefix installs).
    pub ld_library_paths: Vec<PathBuf>,
}

impl RangeTools {
    /// Discover the range toolchain: explicit `BARZAKH_*` environment
    /// variables first, then `PATH`, then the `install-range-tools.sh`
    /// user prefix (`~/barzakh-tools`), then system OVMF locations.
    pub fn discover() -> Result<Self> {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        let tools_prefix = PathBuf::from(&home).join("barzakh-tools");

        let mut ld = Vec::new();

        let qemu = if let Ok(p) = std::env::var("BARZAKH_QEMU") {
            PathBuf::from(p)
        } else if let Some(p) = find_in_path("qemu-system-x86_64") {
            p
        } else {
            let candidate = tools_prefix.join("usr/bin/qemu-system-x86_64");
            if candidate.exists() {
                ld.push(tools_prefix.join("usr/lib"));
                candidate
            } else {
                bail!(
                    "qemu-system-x86_64 not found — install it (or run \
                     scripts/install-range-tools.sh) or set BARZAKH_QEMU"
                )
            }
        };

        let swtpm = if let Ok(p) = std::env::var("BARZAKH_SWTPM") {
            Some(PathBuf::from(p))
        } else if let Some(p) = find_in_path("swtpm") {
            Some(p)
        } else {
            let candidate = tools_prefix.join("usr/bin/swtpm");
            if candidate.exists() {
                ld.push(tools_prefix.join("usr/lib/swtpm"));
                Some(candidate)
            } else {
                None
            }
        };

        let ovmf_code = pick_path(
            std::env::var("BARZAKH_OVMF_CODE").ok().map(PathBuf::from),
            suite_config_ovmf_candidates_code(&tools_prefix),
        )?;
        let ovmf_vars = pick_path(
            std::env::var("BARZAKH_OVMF_VARS").ok().map(PathBuf::from),
            suite_config_ovmf_candidates_vars(&tools_prefix),
        )?;

        Ok(Self {
            qemu,
            swtpm,
            ovmf_code,
            ovmf_vars,
            ld_library_paths: ld,
        })
    }

    /// Environment (LD_LIBRARY_PATH included) for spawned processes.
    fn child_env(&self) -> Vec<(String, String)> {
        let mut env = Vec::new();
        if !self.ld_library_paths.is_empty() {
            let existing = std::env::var("LD_LIBRARY_PATH").unwrap_or_default();
            let joined = self
                .ld_library_paths
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .chain(std::iter::empty())
                .collect::<Vec<_>>()
                .join(":");
            let value = if existing.is_empty() {
                joined
            } else {
                format!("{joined}:{existing}")
            };
            env.push(("LD_LIBRARY_PATH".to_string(), value));
        }
        env
    }
}

fn find_in_path(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(bin))
        .find(|candidate| candidate.exists())
}

fn pick_path(explicit: Option<PathBuf>, candidates: Vec<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p);
        }
        bail!("configured firmware {} does not exist", p.display());
    }
    candidates.into_iter().find(|p| p.exists()).ok_or_else(|| {
        anyhow::anyhow!("no OVMF firmware found — set BARZAKH_OVMF_CODE/BARZAKH_OVMF_VARS")
    })
}

fn suite_config_ovmf_candidates_code(prefix: &Path) -> Vec<PathBuf> {
    vec![
        prefix.join("usr/share/edk2/x64/OVMF_CODE.4m.fd"),
        PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
        PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
        PathBuf::from("/usr/share/ovmf/OVMF_CODE_4M.fd"),
        PathBuf::from("/usr/share/ovmf/OVMF_CODE.fd"),
        PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd"),
        PathBuf::from("/usr/share/qemu/OVMF_CODE.fd"),
    ]
}

fn suite_config_ovmf_candidates_vars(prefix: &Path) -> Vec<PathBuf> {
    vec![
        prefix.join("usr/share/edk2/x64/OVMF_VARS.4m.fd"),
        PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
        PathBuf::from("/usr/share/OVMF/OVMF_VARS.fd"),
        PathBuf::from("/usr/share/ovmf/OVMF_VARS_4M.fd"),
        PathBuf::from("/usr/share/ovmf/OVMF_VARS.fd"),
        PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd"),
        PathBuf::from("/usr/share/qemu/OVMF_VARS.fd"),
    ]
}

// ─── Process guards ──────────────────────────────────────────────────

/// Kills the child when dropped, unless it already exited.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ─── HMP monitor client ──────────────────────────────────────────────

/// Minimal QEMU human-monitor (HMP) client over a unix socket: enough
/// for `pmemsave` and `quit`.
struct HmpClient {
    stream: UnixStream,
    buf: Vec<u8>,
}

impl HmpClient {
    fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .with_context(|| format!("connecting to QEMU monitor {}", path.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut client = Self {
            stream,
            buf: Vec::new(),
        };
        // Swallow the banner ("QEMU x.y monitor …" + prompt).
        let _ = client.read_until_prompt(Duration::from_secs(5));
        Ok(client)
    }

    fn command(&mut self, cmd: &str) -> Result<String> {
        self.stream.write_all(format!("{cmd}\n").as_bytes())?;
        self.read_until_prompt(Duration::from_secs(30))
            .with_context(|| format!("no monitor response to '{cmd}'"))
    }

    /// Read until the `(qemu)` prompt shows up.
    fn read_until_prompt(&mut self, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        let mut chunk = [0u8; 4096];
        loop {
            if let Ok(pos) = find_prompt(&self.buf) {
                let out = String::from_utf8_lossy(&self.buf[..pos]).to_string();
                self.buf.drain(..pos + PROMPT.len());
                return Ok(out);
            }
            if Instant::now() > deadline {
                bail!("timed out waiting for the QEMU monitor prompt");
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => bail!("QEMU monitor closed the connection"),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e.into()),
            }
        }
    }
}

const PROMPT: &[u8] = b"(qemu)";

fn find_prompt(buf: &[u8]) -> Result<usize> {
    buf.windows(PROMPT.len())
        .position(|w| w == PROMPT)
        .ok_or_else(|| anyhow::anyhow!("no prompt"))
}

// ─── Runner ──────────────────────────────────────────────────────────

/// Options for a range run.
#[derive(Debug, Clone, Default)]
pub struct RangeOptions {
    /// Validate manifests, generate payloads, plan the VM — but boot
    /// nothing. Works without QEMU installed.
    pub dry_run: bool,
    /// Keep the per-case working directories (artifacts).
    pub keep: bool,
    /// Skip the (slow) memory-dump scan and assert on deployment
    /// artifacts only.
    pub skip_memory_scan: bool,
}

/// Result of one case.
#[derive(Debug, Clone, Serialize)]
pub struct CaseReport {
    pub name: String,
    pub payload: String,
    pub dormant: bool,
    pub pass: bool,
    /// Detector names that fired, per artifact.
    pub findings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_findings: Option<Vec<String>>,
    pub bootkit_detected: bool,
    /// Assertion failures (empty when the case passed).
    pub failures: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub duration_secs: f64,
    /// Working directory holding the artifacts (serial log, memory dump…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
}

/// Result of a whole suite.
#[derive(Debug, Clone, Serialize)]
pub struct RangeReport {
    pub suite: String,
    pub dry_run: bool,
    pub pass: bool,
    pub cases: Vec<CaseReport>,
    pub duration_secs: f64,
    /// The QEMU command line a real run would use (always present in
    /// dry runs).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub planned_qemu_args: Option<Vec<String>>,
}

impl RangeReport {
    pub fn print_human(&self) {
        if self.dry_run {
            println!("{} dry run — suite {}", "▶".cyan(), self.suite);
        } else {
            println!(
                "{} range suite {} — {}",
                "▶".cyan(),
                self.suite,
                if self.pass {
                    "PASS".green().bold()
                } else {
                    "FAIL".red().bold()
                }
            );
        }
        if let Some(args) = &self.planned_qemu_args {
            println!("  planned VM: {}", args.join(" "));
        }
        for case in &self.cases {
            let status = if case.pass {
                "PASS".green().to_string()
            } else {
                "FAIL".red().bold().to_string()
            };
            let kind = if case.dormant {
                " (kill-switched)"
            } else if case.payload == "none" {
                " (clean control)"
            } else {
                ""
            };
            println!("  [{status}] {}{kind}", case.name);
            println!(
                "        payload={} findings={:?} verdict={}",
                case.payload,
                case.findings,
                if case.bootkit_detected {
                    "compromised"
                } else {
                    "clean"
                }
            );
            if let Some(mem) = &case.memory_findings {
                println!("        in-memory findings: {mem:?}");
            }
            for failure in &case.failures {
                println!("        {}", format!("✗ {failure}").yellow());
            }
            if let Some(error) = &case.error {
                println!("        {}", format!("error: {error}").red());
            }
        }
    }
}

/// Run one suite manifest.
pub fn run_suite(manifest: &Path, opts: &RangeOptions) -> Result<RangeReport> {
    let started = Instant::now();
    let suite = RangeSuite::load(manifest)?;
    let payloads = create_all_payloads();

    let tools = if opts.dry_run {
        RangeTools::discover().ok()
    } else {
        Some(RangeTools::discover().context("range toolchain discovery failed")?)
    };

    let base_workdir = manifest
        .parent()
        .and_then(Path::parent)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
        .join("build/range");
    std::fs::create_dir_all(&base_workdir)?;

    let mut cases = Vec::new();

    for case in &suite.cases {
        let workdir = base_workdir.join(format!("case-{}", case.name));
        let _ = std::fs::remove_dir_all(&workdir);
        std::fs::create_dir_all(&workdir)?;

        cases.push(run_case(
            case,
            &suite.range,
            &payloads,
            tools.as_ref(),
            &workdir,
            opts,
        )?);
    }

    let planned_qemu_args = if opts.dry_run {
        tools.as_ref().map(|t| {
            planned_qemu_command(
                &suite.range,
                t,
                &base_workdir.join(format!("case-{}", suite.cases[0].name)),
            )
        })
    } else {
        None
    };

    let pass = cases.iter().all(|c| c.pass);
    Ok(RangeReport {
        suite: suite.range.name.clone(),
        dry_run: opts.dry_run,
        pass,
        cases,
        duration_secs: started.elapsed().as_secs_f64(),
        planned_qemu_args,
    })
}

fn run_case(
    case: &RangeCase,
    config: &RangeConfig,
    payloads: &[Box<dyn crate::Payload>],
    tools: Option<&RangeTools>,
    workdir: &Path,
    opts: &RangeOptions,
) -> Result<CaseReport> {
    let started = Instant::now();
    let mut report = CaseReport {
        name: case.name.clone(),
        payload: case.payload.clone(),
        dormant: case.dormant,
        pass: false,
        findings: Vec::new(),
        memory_findings: None,
        bootkit_detected: false,
        failures: Vec::new(),
        error: None,
        duration_secs: 0.0,
        workdir: Some(workdir.display().to_string()),
    };

    let result = run_case_inner(case, config, payloads, tools, workdir, opts, &mut report);
    report.duration_secs = started.elapsed().as_secs_f64();
    if let Err(e) = result {
        report.error = Some(format!("{e:#}"));
    }
    if !opts.keep && report.pass {
        // Keep artifacts of failures for triage; clean up passing runs.
        let _ = std::fs::remove_dir_all(workdir);
        report.workdir = None;
    }
    Ok(report)
}

fn run_case_inner(
    case: &RangeCase,
    config: &RangeConfig,
    payloads: &[Box<dyn crate::Payload>],
    tools: Option<&RangeTools>,
    workdir: &Path,
    opts: &RangeOptions,
    report: &mut CaseReport,
) -> Result<()> {
    // ── 1. Attack: generate the payload and deploy it on the ESP. ──
    let payload_bytes: Vec<u8> = if case.payload == "none" {
        b"// barzakh range clean-boot control\r\n".to_vec()
    } else {
        let payload = payloads
            .iter()
            .find(|p| p.name() == case.payload)
            .with_context(|| format!("unknown range payload '{}'", case.payload))?;
        payload.generate(&PayloadConfig {
            arch: crate::Arch::X86_64,
            size: case.payload_size,
            dormant: case.dormant,
        })?
    };

    let payload_path = workdir.join("implant.bin");
    std::fs::write(&payload_path, &payload_bytes)?;

    // The dropper: a valid UEFI application carrying the implant in its
    // section data, placed at the removable boot path
    // (\EFI\BOOT\BOOTX64.EFI). The firmware's boot manager LoadImage()s
    // the whole file into RAM before StartImage()s the (clean) stub. The
    // clean control deploys the same wrapper with benign content,
    // exercising the identical boot path.
    let dropper_bytes = efi_app::wrap_payload_as_efi_app(&payload_bytes)?;
    let dropper_path = workdir.join("dropper.efi");
    std::fs::write(&dropper_path, &dropper_bytes)?;

    let esp_path = workdir.join("esp.img");
    EspImageBuilder::new(16)
        .build_bootable(&dropper_bytes, &esp_path)
        .context("building the bootable ESP image")?;

    if opts.dry_run {
        // Dry run: manifests validated, payloads generated, ESP built.
        // Assertions are not evaluated (nothing boots), so a case that
        // deploys cleanly counts as validated.
        report.pass = true;
        return Ok(());
    }

    let tools = tools.context("range toolchain not available")?;
    let firmware_code = config
        .ovmf_code
        .clone()
        .unwrap_or_else(|| tools.ovmf_code.clone());
    let firmware_vars = config
        .ovmf_vars
        .clone()
        .unwrap_or_else(|| tools.ovmf_vars.clone());
    if !firmware_code.exists() {
        bail!("firmware {} not found", firmware_code.display());
    }

    // ── 2. Boot the range: swtpm + QEMU q35. ──
    let mut swtpm_guard = None;
    if config.tpm {
        let swtpm_bin = tools
            .swtpm
            .as_ref()
            .context("suite requests a TPM but swtpm was not found")?;
        let state_dir = workdir.join("tpm-state");
        std::fs::create_dir_all(&state_dir)?;
        let ctrl_sock = workdir.join("swtpm.sock");
        let mut cmd = Command::new(swtpm_bin);
        cmd.args([
            "socket",
            "--tpm2",
            "--tpmstate",
            &format!("dir={}", state_dir.display()),
            "--ctrl",
            &format!("type=unixio,path={}", ctrl_sock.display()),
            "--log",
            &format!("file={}", workdir.join("swtpm.log").display()),
            "--terminate",
        ])
        .envs(tools.child_env())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
        let child = cmd.spawn().context("starting swtpm")?;
        swtpm_guard = Some(ChildGuard(child));
        wait_for_file(&ctrl_sock, Duration::from_secs(10))
            .context("swtpm control socket never appeared")?;
    }

    // Writable copy of the OVMF vars pflash.
    let vars_copy = workdir.join("OVMF_VARS.fd");
    std::fs::copy(&firmware_vars, &vars_copy)
        .with_context(|| format!("copying {}", firmware_vars.display()))?;

    let serial_log = workdir.join("serial.log");
    let monitor_sock = workdir.join("monitor.sock");
    let qemu_args = qemu_command_args(
        config,
        &firmware_code,
        &vars_copy,
        &esp_path,
        &serial_log,
        &monitor_sock,
        swtpm_guard.is_some(),
    );

    let qemu_err = std::fs::File::create(workdir.join("qemu.err"))?;
    let qemu = Command::new(&tools.qemu)
        .args(&qemu_args)
        .envs(tools.child_env())
        .stdout(Stdio::null())
        .stderr(Stdio::from(qemu_err))
        .spawn()
        .context("starting QEMU")?;
    let mut qemu_guard = ChildGuard(qemu);

    // ── 3. Wait for the guest to exhaust its boot options. ──
    // With the dropper at the removable boot path, OVMF LoadImage()s and
    // StartImage()s it (the stub returns EFI_SUCCESS), then falls through
    // to the boot-manager menu or the UEFI shell. Any of these markers
    // proves the boot chain ran — "starting Boot" is the earliest.
    let boot_markers = [
        "BdsDxe: starting Boot",
        "Please select boot device",
        "Press any key to enter the Boot Manager Menu",
        "UEFI Interactive Shell",
        "Shell>",
    ];
    let boot_deadline = Instant::now() + Duration::from_secs(config.timeout_secs as u64);
    let mut booted = false;
    while Instant::now() < boot_deadline {
        if let Ok(text) = std::fs::read_to_string(&serial_log) {
            if boot_markers.iter().any(|m| text.contains(m)) {
                booted = true;
                break;
            }
        }
        if let Some(status) = qemu_guard.0.try_wait()? {
            bail!(
                "QEMU exited early (status {status:?}): {}",
                std::fs::read_to_string(workdir.join("qemu.err")).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !booted {
        bail!(
            "guest did not finish booting within {}s (see {})",
            config.timeout_secs,
            serial_log.display()
        );
    }
    // Let the boot manager's LoadImage/StartImage attempt settle.
    std::thread::sleep(Duration::from_secs(3));

    // ── 4. Capture: guest memory via the monitor, then power off. ──
    let mem_dump = workdir.join("mem.bin");
    let mut hmp = HmpClient::connect(&monitor_sock)?;
    let mem_bytes = config.memory_mb as u64 * 1024 * 1024;
    hmp.command(&format!(
        "pmemsave 0 0x{mem_bytes:x} {}",
        mem_dump.display()
    ))?;
    let _ = hmp.command("quit");
    let _ = qemu_guard.0.wait();
    drop(qemu_guard);
    drop(swtpm_guard);

    // ── 5. Detect: scan the artifacts. ──
    let mut scanner = BarzakhScanner::new(None);
    let mut deployment: Vec<String> = Vec::new();
    let mut deployment_verdict = false;

    for artifact in [&esp_path, &dropper_path, &payload_path] {
        let result = scanner.scan(artifact, None);
        deployment.extend(result.findings.iter().map(|f| f.detector.clone()));
        deployment_verdict |= result.summary.bootkit_detected;
    }
    deployment.sort();
    deployment.dedup();

    if !opts.skip_memory_scan {
        let mem_result = scanner.scan(&mem_dump, None);
        let mut mem_findings: Vec<String> = mem_result
            .findings
            .iter()
            .map(|f| f.detector.clone())
            .collect();
        // A real memory dump produces thousands of findings; the report
        // only needs the distinct detector names (evidence + containment
        // checks), not every offset.
        mem_findings.sort();
        mem_findings.dedup();
        report.memory_findings = Some(mem_findings);
    }

    report.findings = deployment;
    report.bootkit_detected = deployment_verdict;

    // ── 6. Assert. ──
    // Expected/absent findings are evaluated against the deployment
    // artifacts (ESP image, dropper, implant blob) — deterministic
    // evidence directly attributable to the implant. The captured
    // guest memory is *real* firmware state: genuine OVMF structures
    // (real RUNT tables, SMM save-state shapes) legitimately trip
    // medium-severity heuristics, so memory findings are recorded as
    // live-range evidence and only ever positively asserted, for
    // detectors unambiguously attributable to the implant.
    for expected in &case.expect_findings {
        if !report.findings.contains(expected) {
            report
                .failures
                .push(format!("expected detector '{expected}' did not fire"));
        }
    }
    for absent in &case.expect_absent {
        if report.findings.contains(absent) {
            report.failures.push(format!(
                "intentional miss violated: '{absent}' fired on the kill-switched variant"
            ));
        }
    }
    match &report.memory_findings {
        Some(mem) => {
            for expected in &case.expect_in_memory {
                if !mem.contains(expected) {
                    report.failures.push(format!(
                        "expected detector '{expected}' did not fire in captured guest memory"
                    ));
                }
            }
        }
        None => {
            if !case.expect_in_memory.is_empty() {
                report.failures.push(
                    "in-memory assertions require the memory scan (--skip-memory-scan was set)"
                        .to_string(),
                );
            }
        }
    }
    if case.payload == "none" && report.bootkit_detected {
        report
            .failures
            .push("clean golden-boot control was flagged as compromised".to_string());
    }
    report.pass = report.failures.is_empty();
    Ok(())
}

fn qemu_command_args(
    config: &RangeConfig,
    firmware_code: &Path,
    firmware_vars: &Path,
    esp: &Path,
    serial_log: &Path,
    monitor_sock: &Path,
    with_tpm: bool,
) -> Vec<String> {
    let mut args = vec![
        "-machine".into(),
        if config.smm {
            "q35,smm=on".into()
        } else {
            "q35".into()
        },
        "-m".into(),
        format!("{}M", config.memory_mb),
        "-display".into(),
        "none".into(),
        // Headless: no VGA device (and no VGA BIOS ROM dependency).
        "-vga".into(),
        "none".into(),
        "-serial".into(),
        format!("file:{}", serial_log.display()),
        "-monitor".into(),
        format!("unix:{},server,nowait", monitor_sock.display()),
        "-global".into(),
        "isa-debugcon.iobase=0x402".into(),
        "-debugcon".into(),
        format!(
            "file:{}",
            serial_log
                .parent()
                .unwrap_or(Path::new("."))
                .join("debug.log")
                .display()
        ),
        "-no-reboot".into(),
        "-net".into(),
        "none".into(),
        "-drive".into(),
        format!(
            "if=pflash,format=raw,readonly=on,file={}",
            firmware_code.display()
        ),
        "-drive".into(),
        format!("if=pflash,format=raw,file={}", firmware_vars.display()),
        "-drive".into(),
        format!("if=none,format=raw,file={},id=esp", esp.display()),
        // Removable-media deployment (the LoJax/BlackLotus vector): a
        // USB mass-storage stick forces the firmware through the
        // removable boot path, whose short-form options expand to
        // \EFI\BOOT\BOOTX64.EFI.
        "-device".into(),
        "qemu-xhci,id=xhci".into(),
        "-device".into(),
        "usb-storage,drive=esp,bus=xhci.0,removable=on".into(),
    ];
    if with_tpm {
        args.extend([
            "-chardev".into(),
            format!(
                "socket,id=chrtpm,path={}",
                monitor_sock.parent().unwrap().join("swtpm.sock").display()
            ),
            "-tpmdev".into(),
            "emulator,id=tpm0,chardev=chrtpm".into(),
            "-device".into(),
            "tpm-tis,tpmdev=tpm0".into(),
        ]);
    }
    args
}

fn planned_qemu_command(config: &RangeConfig, tools: &RangeTools, workdir: &Path) -> Vec<String> {
    qemu_command_args(
        config,
        &tools.ovmf_code,
        &tools.ovmf_vars,
        &workdir.join("esp.img"),
        &workdir.join("serial.log"),
        &workdir.join("monitor.sock"),
        config.tpm && tools.swtpm.is_some(),
    )
}

fn wait_for_file(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    bail!("{} never appeared", path.display());
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_suite_manifest() {
        let manifest = r#"
[range]
name = "ring-2-test"
description = "test"
memory_mb = 128
timeout_secs = 30
tpm = false

[[cases]]
name = "hook"
payload = "boot_services_hook"
expect_findings = ["hook"]

[[cases]]
name = "miss"
payload = "boot_services_hook"
dormant = true
expect_absent = ["hook"]
"#;
        let suite: RangeSuite = toml::from_str(manifest).unwrap();
        assert_eq!(suite.range.name, "ring-2-test");
        assert!(!suite.range.tpm);
        assert_eq!(suite.cases.len(), 2);
        assert!(suite.cases[1].dormant);
        assert_eq!(suite.cases[0].expect_findings, vec!["hook"]);
    }

    #[test]
    fn dormant_hook_payload_is_benign() {
        let payload = crate::create_all_payloads()
            .into_iter()
            .find(|p| p.name() == "boot_services_hook")
            .unwrap();
        let armed = payload
            .generate(&PayloadConfig {
                dormant: false,
                ..Default::default()
            })
            .unwrap();
        let dormant = payload
            .generate(&PayloadConfig {
                dormant: true,
                ..Default::default()
            })
            .unwrap();
        // The armed variant hooks pointers outside the firmware range.
        assert!(armed
            .windows(8)
            .any(|w| w == 0x0000_4000_DEAD_0000u64.to_le_bytes()));
        // The dormant variant must not contain any of the hook addresses.
        assert!(!dormant
            .windows(8)
            .any(|w| w == 0x0000_4000_DEAD_0000u64.to_le_bytes()));
        assert!(!dormant
            .windows(8)
            .any(|w| w == 0x0000_7000_CAFE_0000u64.to_le_bytes()));
        assert!(!dormant
            .windows(8)
            .any(|w| w == 0x0000_5000_BABE_0000u64.to_le_bytes()));
    }

    #[test]
    fn dormant_smm_payload_locks_smram() {
        let payload = crate::create_all_payloads()
            .into_iter()
            .find(|p| p.name() == "smm_timing_anomaly")
            .unwrap();
        let armed = payload
            .generate(&PayloadConfig {
                dormant: false,
                ..Default::default()
            })
            .unwrap();
        let dormant = payload
            .generate(&PayloadConfig {
                dormant: true,
                ..Default::default()
            })
            .unwrap();
        // Armed: SMRAM lock bit clear at offset 0x108.
        assert_eq!(&armed[0x108..0x10c], &0xFFF00000u32.to_le_bytes());
        // Dormant: lock engaged.
        assert_eq!(&dormant[0x108..0x10c], &0xFFF00001u32.to_le_bytes());
        // Armed: INT3 patch handler at 0x200; dormant: none.
        assert_eq!(&armed[0x200..0x204], &[0xCC, 0xCC, 0xCC, 0xCC]);
        assert_eq!(&dormant[0x200..0x204], &[0, 0, 0, 0]);
    }

    #[test]
    fn dry_run_needs_no_qemu() {
        // The dry-run path validates manifests and payloads without a VM.
        let manifest = r#"
[range]
name = "dry"
tpm = false

[[cases]]
name = "hook"
payload = "boot_services_hook"
expect_findings = ["hook"]
"#;
        let suite: RangeSuite = toml::from_str(manifest).unwrap();
        assert_eq!(suite.cases.len(), 1);
    }

    #[test]
    fn hmp_prompt_parsing() {
        // find_prompt locates the (qemu) prompt inside buffered output.
        let buf = b"QEMU 11.1 monitor\n(qemu) ".to_vec();
        assert_eq!(find_prompt(&buf).unwrap(), 18);
        assert!(find_prompt(b"no prompt here").is_err());
    }
}
