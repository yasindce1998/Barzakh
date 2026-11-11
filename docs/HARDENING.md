# Trustworthy scans and deployment hardening

## Scan outcome contract

`scan --json` now returns a **ScanResult object**, not a findings array. Consumers
should read `.findings` and check `.status`, `.errors`, and `.detector_runs`.
JSON reports preserve the same fields plus `timestamp`; history stores full
results with input SHA-256. Older history rows may lack full outcomes.

- `complete`: selected detectors finished without execution errors or missing
  required evidence; this is **not** a guarantee that firmware is benign.
- `partial`: some detectors finished, but errors, unknown selections, or missing
  evidence prevent a complete assessment.
- `failed`: no detector successfully assessed the input, or input validation failed.
- Detector states: `passed`, `findings`, `not_applicable`, `insufficient_evidence`, `error`.
- Exit codes: **0** complete/no positive bootkit verdict, **1** detection,
  **2** failed/incomplete or command error. Incompleteness takes precedence over detection.

Inputs must be nonempty regular files. Default size limit is 512 MiB; CLI users
can raise `--max-image-bytes` explicitly for larger dumps. All built-in and bundled
extension detectors use one immutable owned snapshot, avoiding repeated reads and
file-backed mmap mutation races. SHA-256 and attached TCG parsing are cached.
Legacy external path-based detector plugins still work but must implement
`detect_context` to gain snapshot consistency.

Measure a full detector sweep on real images with
`cargo run --release -p barzakh-core --example benchmark_scan -- IMAGE 10`.
It reports image size/hash, p50/p95 latency including read/hash, and Linux process
peak RSS (null on other platforms). Run each image in a fresh process for
comparable high-water marks; record CPU, firmware family, and build profile.
An illustrative local release-mode run on `OVMF_CODE.4m.fd` (3,653,632 bytes,
three measured runs after warmup) reported p50 1,527 ms, p95 1,634 ms, and 64,364
KiB process peak RSS. This is not a cross-machine performance guarantee or a
before/after comparison; the <500 ms target remains unmet on that measurement.

JSON reports are available even for failed scans; findings-only HTML/Markdown/
SARIF/CSV reports are refused for incomplete scans. The dashboard shows
inconclusive rather than clean for failed/partial scans.

## Server safety

The server defaults to `127.0.0.1`, requires `BARZAKH_API_KEY` or `--api-key`, and
permits unauthenticated development only with `--insecure-dev` on loopback.
Use a TLS reverse proxy for remote access. The Compose deployment requires a
nonempty secret and publishes only `127.0.0.1:8420` on the host.

```sh
export BARZAKH_API_KEY="$(openssl rand -hex 32)"
barzakh-server --scan-root /srv/firmware --payloads-dir ./payloads
curl -H "X-API-Key: $BARZAKH_API_KEY" http://127.0.0.1:8420/api/detectors
```

Approved `--scan-root` directories constrain scan, schedule, and KB reads.
Canonicalization rejects traversal and symlinks resolving outside roots. **Roots
and their parent directories must be controlled by the operator, not writable by
untrusted local users**: path checks are not an OS sandbox and cannot eliminate
all local rename/symlink races. Mount input directories read-only, run unprivileged,
and isolate this service from sensitive host paths.

Manual/scheduled scans share `--max-concurrent-scans` (2) and
`--max-queued-scans` (8). Overload returns HTTP 429. Queued scans revalidate the
target when starting. The input cap is `--max-image-bytes` (512 MiB); generation
requests accept 4 KiB–16 MiB and schedules are capped at 128. Schedules remain
in-memory and must be recreated after restart.

Blocking workers are **not** killable CPU sandboxes. For hostile public uploads,
use process/container isolation with CPU, memory and wall-clock limits; do not
expose this research API directly to the Internet.

## Independent validation

`validate --corpus DIR --manifest DIR/corpus.toml --strict --split test` verifies
explicit labels and SHA-256 hashes, rejects path escapes/duplicates and cross-split
family leakage, and emits verdict and per-detector precision/recall. Omit
`--strict` only for exploratory runs; missing samples are reported, not counted.
An incomplete scan fails manifest validation instead of improving accuracy.

Schema (repeat `[[samples]]` for reviewed positive and negative controls):

```toml
version = 1
provenance = "independent" # or synthetic; never combine the claims
[[samples]]
path = "clean/vendor-model-version.bin"
sha256 = "<64 reviewed hexadecimal characters>"
malicious = false
vendor = "vendor-name"
family = "vendor-model-family"
arch = "x86_64"
split = "test"
expected_detectors = []
```

Per-detector negatives come from clean samples; malicious samples contribute
only where `expected_detectors` gives reviewed ground truth. Undefined metrics
are null, not misleading zeroes. Related firmware families must stay in one
split. Expand with licensed vendor capsules, coreboot builds, ARM/RISC-V images,
and independently labeled paired captures; **this change does not supply those
artifacts or establish new real-world accuracy**.

The existing real-corpus test verifies hashes of present declared samples.
`BARZAKH_REQUIRE_REAL_CORPUS=1` requires both classes and all declared entries.
Default CI fetches only the licensed clean set; real-malware recall remains
unmeasured until operators provision and hash approved samples.

Legacy synthetic regression explicitly lists `auth_var_rollback` and
`nvram_silent_downgrade` as incomplete because no same-boot log accompanies
their policy variables. Their incompleteness is not counted as a true negative
or a successful detection.

## CI, fuzzing, and releases

The workspace toolchain is pinned in `rust-toolchain.toml`. CI tests/clippy cover
all workspace targets with the lockfile, and generated capability docs are checked.
Weekly protocol/harness crashes and malformed JSON fail rather than becoming
placeholder success output. Coverage-guided parser fuzzing invokes detectors
directly so scanner panic recovery cannot hide crashes.

Minimize saved libFuzzer artifacts, then add them to deterministic regression
tests before fixing the bug. Run `cargo +nightly-2026-10-01 fuzz tmin parsers PATH`
inside the workspace. Do not commit sensitive firmware fragments.

Tagged releases generate an SPDX **source dependency** SBOM and GitHub OIDC
provenance/SBOM attestations. Verify with:

```sh
gh attestation verify ./barzakh-scanner-<target> --repo yasindce1998/Barzakh
```

The SBOM does not claim to enumerate every cross-toolchain/system component.
Attestations require GitHub repository permissions and must be exercised on the
next authorized tag. No signing keys or credentials are created by this change.
EFI artifact signing/HSM enforcement and bit-identical cross-machine builds are
not established by the Rust release workflow.
