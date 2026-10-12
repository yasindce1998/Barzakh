# Barzakh Test Corpus

This directory contains test samples for validating the Barzakh Scanner's detection capabilities.

## Directory Structure

```
corpus/
├── malicious/          # Known bootkit samples
│   ├── blacklotus/     # BlackLotus (CVE-2023-24932)
│   ├── cosmicstrand/   # CosmicStrand (MSR hooking)
│   ├── lojax/          # LoJax (SPI persistence)
│   ├── moonbounce/     # MoonBounce (FV injection)
│   └── mosaicregressor/# MosaicRegressor
├── benign/             # Clean firmware samples
│   ├── dell/           # Dell firmware
│   ├── hp/             # HP firmware
│   ├── lenovo/         # Lenovo firmware
│   ├── asus/           # ASUS firmware
│   └── msi/            # MSI firmware
└── synthetic/          # Generated test cases
    ├── hook_tests/     # Hook detection tests
    ├── pcr_tests/      # PCR validation tests
    ├── entropy_tests/  # Entropy analysis tests
    └── fv_tests/       # FV parsing tests
```

## Sample Metadata

Each sample includes a JSON metadata file with:

```json
{
  "name": "Sample Name",
  "type": "malicious|benign|synthetic",
  "category": "bootkit|firmware|test",
  "sha256": "hash",
  "source": "origin",
  "date_acquired": "YYYY-MM-DD",
  "expected_detections": {
    "hooks": ["ExitBootServices", "LoadImage"],
    "pcr_modifications": [0, 7],
    "memory_regions": [[0x100000, 0x200000]],
    "entropy_anomalies": 2,
    "fv_modifications": 1
  },
  "notes": "Additional information"
}
```

## Usage

### Generating the Synthetic Corpus

```bash
# Generate all malicious + clean pairs using the Rust adversary binary
scripts/generate-corpus.sh

# Or with immediate validation
scripts/generate-corpus.sh --validate
```

### Running Validation

```bash
# Validate all synthetic samples (TPR + FPR)
barzakh-adversary validate --corpus tests/corpus/synthetic/

# Validate using the scanner's full confusion-matrix mode
barzakh-scanner validate --corpus tests/corpus/synthetic/

# Validate E2E scan results from CI
python3 tests/validate_ci_results.py <scan_results.json>
```

### Adding New Samples

1. Place binary in appropriate directory
2. Create metadata JSON file
3. Run validation to verify detection

```bash
# Add sample
cp new_sample.bin corpus/malicious/newsample/
cp metadata.json corpus/malicious/newsample/

# Validate
barzakh-scanner scan --target corpus/malicious/newsample/new_sample.bin
```

## Acquisition Guidelines

### Malicious Samples

**IMPORTANT**: Only use samples for research purposes in isolated environments.

Sources:
- VirusTotal (with appropriate API access)
- Academic research repositories
- Coordinated disclosure programs
- Synthetic generation (preferred for CI/CD)

### Benign Samples

Sources:
- Vendor websites (Dell, HP, Lenovo, etc.)
- LVFS (Linux Vendor Firmware Service)
- Direct hardware extraction (with permission)

### Legal Considerations

- Ensure proper authorization for all samples
- Follow responsible disclosure practices
- Comply with local laws regarding malware possession
- Use only in isolated research environments

## Synthetic Test Generation

For CI/CD and automated testing, generate synthetic samples using the Rust adversary binary:

```bash
# Generate a full synthetic corpus (malicious + clean pairs for all 116 payloads)
scripts/generate-corpus.sh

# Or use the adversary binary directly
barzakh-adversary corpus --output tests/corpus/synthetic/

# Generate a single payload for targeted testing
barzakh-adversary generate --payload acpi_backdoor --output corpus/synthetic/acpi_test.bin

# Inject a payload into an existing firmware image (Phase 3 lab testing)
barzakh-adversary inject-single \
    --input original_firmware.bin \
    --output test_phase3.bin \
    --payload acpi_backdoor
```

## Validation Metrics

The corpus validation framework calculates:

- **True Positive Rate (TPR)**: Correctly detected malicious samples
- **False Positive Rate (FPR)**: Benign samples incorrectly flagged
- **True Negative Rate (TNR)**: Correctly identified benign samples
- **False Negative Rate (FNR)**: Malicious samples missed

Target metrics:
- TPR ≥ 85%
- FPR ≤ 5%
- TNR ≥ 95%
- FNR ≤ 15%

## Known Samples

### BlackLotus
- **Type**: UEFI Bootkit
- **CVE**: CVE-2023-24932
- **Technique**: Secure Boot bypass via vulnerable bootloader
- **Expected Detections**: SetVariable hook, Secure Boot policy modification

### CosmicStrand
- **Type**: UEFI Firmware Rootkit
- **Technique**: MSR hooking (IA32_LSTAR)
- **Expected Detections**: MSR modifications, syscall redirection

### LoJax
- **Type**: UEFI Firmware Implant
- **Technique**: SPI flash persistence
- **Expected Detections**: FV modifications, persistent DXE driver

### MoonBounce
- **Type**: UEFI Bootkit
- **Technique**: DXE driver injection
- **Expected Detections**: FV modifications, hook trampolines

### MosaicRegressor
- **Type**: UEFI Firmware Implant
- **Technique**: Multiple persistence mechanisms
- **Expected Detections**: Multiple hooks, FV modifications, high entropy

## References

- [BlackLotus Analysis](https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit/)
- [CosmicStrand Report](https://securelist.com/cosmicstrand-uefi-firmware-rootkit/106973/)
- [LoJax Technical Details](https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-wild/)
- [MoonBounce Analysis](https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/)

## Disclaimer

This corpus is for security research and educational purposes only. Unauthorized use of malicious samples may be illegal. Always follow responsible disclosure practices and local laws.