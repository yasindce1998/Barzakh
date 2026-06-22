use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const KERNEL_SPACE_MIN: u64 = 0xFFFF800000000000;

pub struct MeDmaDetector;

impl Default for MeDmaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl MeDmaDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_dma_buffer_patterns(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Scan for DMA descriptor structures:
        // source address (8 bytes) + destination address (8 bytes) + length (4 bytes) + status (4 bytes)
        // where addresses are in kernel space (>= 0xFFFF800000000000)

        if data.len() < 24 {
            return findings;
        }

        for i in 0..data.len() - 24 {
            // Parse source address (little-endian u64)
            let src_addr = u64::from_le_bytes(data[i..i + 8].try_into().unwrap_or([0; 8]));

            // Parse destination address (little-endian u64)
            let dst_addr = u64::from_le_bytes(data[i + 8..i + 16].try_into().unwrap_or([0; 8]));

            // Parse length (little-endian u32)
            let length = u32::from_le_bytes(data[i + 16..i + 20].try_into().unwrap_or([0; 4]));

            // Check if either address is in kernel space
            let src_in_kernel = src_addr >= KERNEL_SPACE_MIN && src_addr != u64::MAX;
            let dst_in_kernel = dst_addr >= KERNEL_SPACE_MIN && dst_addr != u64::MAX;

            // Both addresses must be non-zero and length must be reasonable
            if (src_in_kernel || dst_in_kernel)
                && src_addr != 0
                && dst_addr != 0
                && length > 0
                && length < 0x1000000
            // < 16MB - reasonable DMA transfer
            {
                let target_desc = if src_in_kernel && dst_in_kernel {
                    "both source and destination in kernel space"
                } else if dst_in_kernel {
                    "destination targeting kernel memory"
                } else {
                    "source reading from kernel memory"
                };

                findings.push(
                    Finding::new(
                        "me_dma",
                        Severity::High,
                        "ME DMA buffer targeting kernel memory",
                        &format!(
                            "DMA descriptor at offset 0x{:08X}: src=0x{:016X}, \
                             dst=0x{:016X}, len=0x{:08X}. {}.",
                            i, src_addr, dst_addr, length, target_desc
                        ),
                    )
                    .with_confidence(0.60)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", i),
                        "source_address": format!("0x{:016X}", src_addr),
                        "destination_address": format!("0x{:016X}", dst_addr),
                        "length": format!("0x{:08X}", length),
                        "src_in_kernel": src_in_kernel,
                        "dst_in_kernel": dst_in_kernel,
                    }))
                    .with_recommendation(
                        "ME DMA targeting kernel memory indicates potential host memory \
                         compromise via ME engine. Check IOMMU/VT-d configuration.",
                    ),
                );

                // Only report first occurrence to avoid noise
                return findings;
            }
        }

        findings
    }

    fn check_uma_region_access(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Look for ME UMA (Unified Memory Architecture) region access signatures
        // UMA base register: 0x7890
        // PAVP base: 0xFED40000
        let uma_base_reg: &[u8] = &[0x90, 0x78]; // 0x7890 little-endian (16-bit)
        let pavp_base: &[u8] = &[0x00, 0x00, 0xD4, 0xFE]; // 0xFED40000 little-endian

        for (i, window) in data.windows(uma_base_reg.len()).enumerate() {
            if window == uma_base_reg {
                // Check if this is within a code-like region
                // Look for common instruction prefixes nearby
                let context_start = i.saturating_sub(16);
                let context_end = (i + 32).min(data.len());
                let context = &data[context_start..context_end];

                // Simple heuristic: check for x86 instruction-like byte distribution
                let has_code_patterns = context.iter().any(|&b| {
                    // Common x86 instruction prefixes/opcodes
                    b == 0x48 || b == 0x89 || b == 0x8B || b == 0xC7 || b == 0xB8
                });

                if has_code_patterns {
                    findings.push(
                        Finding::new(
                            "me_dma",
                            Severity::Medium,
                            "ME UMA region access pattern detected",
                            &format!(
                                "UMA base register reference (0x7890) at offset 0x{:08X} \
                                 within code-like region. Indicates ME UMA region access.",
                                i
                            ),
                        )
                        .with_confidence(0.50)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "uma_register": "0x7890",
                        })),
                    );
                    break;
                }
            }
        }

        // Also check for PAVP base references
        for (i, window) in data.windows(pavp_base.len()).enumerate() {
            if window == pavp_base {
                let context_start = i.saturating_sub(16);
                let context_end = (i + 32).min(data.len());
                let context = &data[context_start..context_end];

                let has_code_patterns = context
                    .iter()
                    .any(|&b| b == 0x48 || b == 0x89 || b == 0x8B || b == 0xC7 || b == 0xB8);

                if has_code_patterns {
                    findings.push(
                        Finding::new(
                            "me_dma",
                            Severity::Medium,
                            "ME UMA region access pattern detected",
                            &format!(
                                "PAVP base (0xFED40000) reference at offset 0x{:08X} \
                                 within code-like region. Indicates ME protected audio/video \
                                 path memory access.",
                                i
                            ),
                        )
                        .with_confidence(0.50)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", i),
                            "pavp_base": "0xFED40000",
                        })),
                    );
                    break;
                }
            }
        }

        findings
    }

    fn check_dma_shellcode_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Detect DMA write patterns followed by common shellcode prologues
        // at page-aligned boundaries (address & 0xFFF == 0)
        //
        // Common x86_64 shellcode prologues:
        //   0x48 0x31 0xC0 = xor rax, rax
        //   0x48 0x89 0xE5 = mov rbp, rsp
        let shellcode_prologues: &[&[u8]] = &[
            &[0x48, 0x31, 0xC0], // xor rax, rax
            &[0x48, 0x89, 0xE5], // mov rbp, rsp
        ];

        // Look for page-aligned shellcode prologues
        // Page size = 0x1000, so check offsets that are page-aligned
        let page_size: usize = 0x1000;

        for page_start in (0..data.len()).step_by(page_size) {
            if page_start + 3 > data.len() {
                break;
            }

            for prologue in shellcode_prologues {
                if page_start + prologue.len() <= data.len()
                    && data[page_start..page_start + prologue.len()] == **prologue
                {
                    // Verify this looks like code, not just coincidental bytes
                    // Check if there's a DMA-like structure in the preceding page
                    if page_start >= 24 {
                        let prev_page_start = page_start.saturating_sub(page_size);
                        let search_region = &data[prev_page_start..page_start];

                        // Look for kernel-space addresses in the preceding region
                        // (DMA descriptors targeting this page)
                        let has_dma_context = search_region.windows(8).any(|w| {
                            let addr = u64::from_le_bytes(w.try_into().unwrap_or([0; 8]));
                            addr >= KERNEL_SPACE_MIN && addr != u64::MAX
                        });

                        if has_dma_context {
                            let prologue_name = if *prologue == [0x48, 0x31, 0xC0] {
                                "xor rax, rax"
                            } else {
                                "mov rbp, rsp"
                            };

                            findings.push(
                                Finding::new(
                                    "me_dma",
                                    Severity::Critical,
                                    "DMA-injected shellcode detected at page boundary",
                                    &format!(
                                        "Shellcode prologue '{}' detected at page-aligned \
                                         offset 0x{:08X} with DMA descriptor references in \
                                         preceding region. Indicates DMA-based code injection.",
                                        prologue_name, page_start
                                    ),
                                )
                                .with_confidence(0.65)
                                .with_details(serde_json::json!({
                                    "offset": format!("0x{:08X}", page_start),
                                    "prologue": prologue_name,
                                    "page_aligned": true,
                                    "dma_context_in_preceding_page": true,
                                }))
                                .with_recommendation(
                                    "DMA-injected shellcode detected. System memory integrity \
                                     is compromised. Perform cold boot and verify IOMMU/VT-d \
                                     is enabled and properly configured.",
                                ),
                            );
                            return findings;
                        }
                    }
                }
            }
        }

        findings
    }
}

impl Detector for MeDmaDetector {
    fn name(&self) -> &str {
        "me_dma"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        let mut findings = Vec::new();

        findings.extend(self.check_dma_buffer_patterns(&data));
        findings.extend(self.check_uma_region_access(&data));
        findings.extend(self.check_dma_shellcode_injection(&data));

        Ok(findings)
    }
}
