use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

const TDVF_MAGIC: &[u8] = b"TDVF";
const SEV_SNP_VMSA_MARKER: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0xFE, 0x53, 0x4E, 0x50];
const GHCB_MSR_PROTOCOL: &[u8] = &[0x47, 0x48, 0x43, 0x42];
const SNP_GUEST_REQUEST: &[u8] = b"SNP_GUEST_REQ";

pub struct ConfidentialVmDetector;

impl Default for ConfidentialVmDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfidentialVmDetector {
    pub fn new() -> Self {
        Self
    }

    fn check_tdx_injection(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(tdvf_pos) = data.windows(TDVF_MAGIC.len()).position(|w| w == TDVF_MAGIC) {
            let desc_region_end = (tdvf_pos + 128).min(data.len());
            let desc_region = &data[tdvf_pos..desc_region_end];

            let zero_measurement_count = desc_region
                .windows(32)
                .filter(|w| w.iter().all(|&b| b == 0))
                .count();

            if zero_measurement_count >= 2 {
                findings.push(
                    Finding::new(
                        "confidential_vm",
                        Severity::Critical,
                        "TDX firmware descriptor with zeroed measurement fields",
                        &format!(
                            "TDVF descriptor at offset 0x{:08X} contains {} zeroed 32-byte \
                             blocks where MRTD measurements should be. Indicates TDX firmware \
                             injection where the attacker has replaced measurement hashes with \
                             zeros to avoid detection during TD attestation.",
                            tdvf_pos, zero_measurement_count
                        ),
                    )
                    .with_confidence(0.90)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", tdvf_pos),
                        "zeroed_measurements": zero_measurement_count,
                        "technique": "Intel TDX OVMF firmware injection",
                    }))
                    .with_recommendation(
                        "Verify TD attestation report and compare MRTD against known-good OVMF build hash",
                    ),
                );
            }

            let cfv_marker = b"CFV_";
            if let Some(cfv_pos) = desc_region
                .windows(cfv_marker.len())
                .position(|w| w == cfv_marker)
            {
                let abs_cfv = tdvf_pos + cfv_pos;
                findings.push(
                    Finding::new(
                        "confidential_vm",
                        Severity::High,
                        "TDX Configuration Firmware Volume with injection markers",
                        &format!(
                            "Found CFV marker at offset 0x{:08X} within TDVF descriptor region. \
                             Configuration FV is a known target for TDX firmware injection as it \
                             allows attacker-controlled data to be measured into MRTD.",
                            abs_cfv
                        ),
                    )
                    .with_confidence(0.75)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", abs_cfv),
                        "tdvf_offset": format!("0x{:08X}", tdvf_pos),
                    })),
                );
            }
        }

        findings
    }

    fn check_sev_snp_vmpl_confusion(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(vmsa_pos) = data
            .windows(SEV_SNP_VMSA_MARKER.len())
            .position(|w| w == SEV_SNP_VMSA_MARKER)
        {
            let vmpl_offset = vmsa_pos + SEV_SNP_VMSA_MARKER.len();
            if vmpl_offset + 4 < data.len() {
                let vmpl_field = data[vmpl_offset];
                let expected_vmpl = data[vmpl_offset + 1];

                if vmpl_field == 0x00 && expected_vmpl >= 0x02 {
                    findings.push(
                        Finding::new(
                            "confidential_vm",
                            Severity::Critical,
                            "SEV-SNP VMPL confusion: VMPL0 context at VMPL2+ permissions",
                            &format!(
                                "VMSA structure at offset 0x{:08X} declares VMPL level 0 (hypervisor) \
                                 but adjacent permission field indicates VMPL {} (guest). This is a \
                                 VMPL confusion attack allowing guest-level code to execute with \
                                 hypervisor privileges.",
                                vmsa_pos, expected_vmpl
                            ),
                        )
                        .with_confidence(0.92)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", vmsa_pos),
                            "declared_vmpl": 0,
                            "actual_vmpl_context": expected_vmpl,
                            "technique": "AMD SEV-SNP VMPL privilege escalation",
                        }))
                        .with_recommendation(
                            "Update AMD firmware to latest microcode and verify VMPL assignments in GHCB",
                        ),
                    );
                }
            }
        }

        if let Some(ghcb_pos) = data
            .windows(GHCB_MSR_PROTOCOL.len())
            .position(|w| w == GHCB_MSR_PROTOCOL)
        {
            let protocol_region_end = (ghcb_pos + 64).min(data.len());
            if ghcb_pos + 16 < data.len() {
                let privilege_byte = data[ghcb_pos + 12];
                if privilege_byte == 0x00 {
                    findings.push(
                        Finding::new(
                            "confidential_vm",
                            Severity::High,
                            "GHCB MSR protocol with confused privilege indicators",
                            &format!(
                                "GHCB protocol structure at offset 0x{:08X} has VMPL privilege \
                                 field set to 0 (most privileged) in what appears to be a \
                                 guest-initiated communication, suggesting VMPL confusion.",
                                ghcb_pos
                            ),
                        )
                        .with_confidence(0.78)
                        .with_details(serde_json::json!({
                            "offset": format!("0x{:08X}", ghcb_pos),
                            "region_end": format!("0x{:08X}", protocol_region_end),
                        })),
                    );
                }
            }
        }

        if let Some(req_pos) = data
            .windows(SNP_GUEST_REQUEST.len())
            .position(|w| w == SNP_GUEST_REQUEST)
        {
            let vmpl_field_offset = req_pos + SNP_GUEST_REQUEST.len() + 4;
            if vmpl_field_offset < data.len() && data[vmpl_field_offset] == 0x00 {
                findings.push(
                    Finding::new(
                        "confidential_vm",
                        Severity::High,
                        "SNP_GUEST_REQUEST with escalated VMPL field",
                        &format!(
                            "SNP guest request at offset 0x{:08X} has VMPL field set to 0 \
                             (hypervisor level). A legitimate guest request should use VMPL >= 2.",
                            req_pos
                        ),
                    )
                    .with_confidence(0.80)
                    .with_details(serde_json::json!({
                        "offset": format!("0x{:08X}", req_pos),
                        "vmpl_value": 0,
                        "technique": "SEV-SNP VMPL escalation via guest request",
                    })),
                );
            }
        }

        findings
    }
}

impl Detector for ConfidentialVmDetector {
    fn name(&self) -> &str {
        "confidential_vm"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        self.detect_context(&crate::ScanContext::load(target_path)?)
    }

    fn detect_context(&self, context: &crate::ScanContext) -> Result<Vec<Finding>, DetectorError> {
        let data = context.shared_bytes();
        let mut findings = Vec::new();

        findings.extend(self.check_tdx_injection(&data));
        findings.extend(self.check_sev_snp_vmpl_confusion(&data));

        Ok(findings)
    }
}
