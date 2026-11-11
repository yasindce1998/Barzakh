use std::path::Path;

use aho_corasick::AhoCorasick;

use crate::baseline::Baseline;
use crate::detector::{Detector, DetectorError, Finding, Severity};

const BOOTKIT_SIGNATURES: &[&[u8]] = &[
    b"BlackLotus",
    b"ESPecter",
    b"FinSpy",
    b"MosaicRegressor",
    b"CosmicStrand",
    b"MoonBounce",
    // Note: `EB FE` (jmp $) is deliberately NOT a signature — hang loops
    // are idiomatic in legitimate firmware (assert/init-failure paths).
    b"\x48\xB8UEFI_BK!", // custom marker
];

const PE_MAGIC: &[u8] = b"MZ";
const PE_SIGNATURE: &[u8] = b"PE\x00\x00";

pub struct MemoryDetector {
    #[allow(dead_code)]
    baseline: Option<Baseline>,
    signature_matcher: AhoCorasick,
}

impl MemoryDetector {
    pub fn new(baseline: Option<Baseline>) -> Self {
        let signature_matcher = AhoCorasick::new(BOOTKIT_SIGNATURES).expect("valid patterns");
        Self {
            baseline,
            signature_matcher,
        }
    }

    fn detect_pe_in_runtime(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // This check models finding an injected PE in a *memory dump*'s
        // runtime region, scanning page-aligned addresses. Page 0 is the
        // scan target's own image header: when the target is itself a
        // PE/COFF file (an EFI application or driver) its own MZ header is
        // not an injection. Embedded images on later pages still are.
        let mut offset = 0x1000;

        while offset + 2 <= data.len() {
            if &data[offset..offset + 2] == PE_MAGIC && offset + 0x3C + 4 <= data.len() {
                let pe_offset = u32::from_le_bytes(
                    data[offset + 0x3C..offset + 0x3C + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                ) as usize;
                if offset + pe_offset + 4 <= data.len()
                    && &data[offset + pe_offset..offset + pe_offset + 4] == PE_SIGNATURE
                {
                    findings.push(
                            Finding::new(
                                "memory",
                                Severity::High,
                                "PE image found in UEFI runtime memory",
                                &format!(
                                    "A PE/COFF executable was found at offset 0x{:08X} in runtime memory. \
                                     This may indicate injected code.",
                                    offset
                                ),
                            )
                            .with_confidence(0.85)
                            .with_details(serde_json::json!({
                                "offset": format!("0x{:08X}", offset),
                                "pe_offset": pe_offset,
                            })),
                        );
                }
            }
            offset += 0x1000; // page-aligned scan
        }

        findings
    }

    fn detect_trampoline_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // x86_64: FF 25 00 00 00 00 (jmp [rip+0])
        let jmp_rip_pattern: &[u8] = &[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        for (i, window) in data.windows(6).enumerate() {
            if window == jmp_rip_pattern && i + 14 <= data.len() {
                let target = u64::from_le_bytes(data[i + 6..i + 14].try_into().unwrap_or([0; 8]));
                if target != 0 && target != u64::MAX {
                    findings.push(
                        Finding::new(
                            "memory",
                            Severity::High,
                            "Suspicious trampoline detected in memory",
                            &format!(
                                "JMP [RIP+0] trampoline at offset 0x{:08X} targeting 0x{:016X}",
                                i, target
                            ),
                        )
                        .with_confidence(0.75)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "target": format!("0x{:016X}", target),
                            "arch": "x86_64",
                        })),
                    );
                }
            }
        }

        // ARM64: LDR X16, [PC, #8]; BR X16
        let arm64_trampoline: &[u8] = &[0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6];
        for (i, window) in data.windows(8).enumerate() {
            if window == arm64_trampoline && i + 16 <= data.len() {
                findings.push(
                    Finding::new(
                        "memory",
                        Severity::High,
                        "ARM64 trampoline detected in memory",
                        &format!("LDR X16/BR X16 trampoline at offset 0x{:08X}", i),
                    )
                    .with_confidence(0.70)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "arch": "aarch64",
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for MemoryDetector {
    fn name(&self) -> &str {
        "memory"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }
    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        // Signature scanning with Aho-Corasick
        for mat in self.signature_matcher.find_iter(data.as_slice()) {
            let pattern_idx = mat.pattern().as_usize();
            let sig_name = match pattern_idx {
                0 => "BlackLotus",
                1 => "ESPecter",
                2 => "FinSpy",
                3 => "MosaicRegressor",
                4 => "CosmicStrand",
                5 => "MoonBounce",
                6 => "Custom bootkit marker",
                _ => "Unknown",
            };

            findings.push(
                Finding::new(
                    "memory",
                    Severity::Critical,
                    &format!("Known bootkit signature: {}", sig_name),
                    &format!(
                        "Matched bootkit signature '{}' at offset 0x{:08X}",
                        sig_name,
                        mat.start()
                    ),
                )
                .with_confidence(0.95)
                .with_details(serde_json::json!({
                    "signature": sig_name,
                    "offset": format!("0x{:08X}", mat.start()),
                    "length": mat.end() - mat.start(),
                }))
                .with_recommendation("Immediately investigate firmware integrity."),
            );
        }

        // PE detection in runtime regions
        findings.extend(self.detect_pe_in_runtime(&data));

        // Trampoline detection
        findings.extend(self.detect_trampoline_patterns(&data));

        Ok(findings)
    }
}
