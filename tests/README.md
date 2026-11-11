# Barzakh Test Suite

## Scanner Tests (Rust)

The primary test suite lives in the Rust workspace at `src/barzakh-scanner-rs/`.

### Running Tests

```bash
cd src/barzakh-scanner-rs

# Run all tests
cargo test

# Check formatting & lint
cargo fmt --check
cargo clippy -- -D warnings

# Security audit
cargo audit
```

The Rust workspace tests detectors, scan failures/partial outcomes, snapshot consistency,
server authentication and resource limits, reports, baselines, and corpus validation.
See the [generated detector registry](../docs/CAPABILITIES.md) rather than hardcoded counts.

## E2E Tests

End-to-end testing runs via QEMU with a software TPM:

```bash
./scripts/qemu-e2e.sh ./binaries
```

This boots the bootkit in QEMU, extracts memory dumps and PCR values, then runs the scanner against them.

## Test Corpus

The `corpus/` directory contains synthetic firmware samples used for TPR/FPR validation:
- Legacy synthetic validation accepts `malicious_*`/`infected_*` positives and `clean_*` negatives.
- Other files are ignored; incomplete samples are explicitly listed and excluded, never counted as clean.
- Use `validate --manifest` for explicit labels, SHA-256 verification, family-disjoint splits,
  and per-detector metrics. `--strict` requires every sample and both classes.

## CI/CD Integration

Tests run automatically via `.github/workflows/barzakh-ci.yml`:
- `test-scanner-rs`: fmt check, clippy, cargo test
- `security-audit-rs`: cargo audit
- `qemu-e2e`: full end-to-end with QEMU + swtpm
