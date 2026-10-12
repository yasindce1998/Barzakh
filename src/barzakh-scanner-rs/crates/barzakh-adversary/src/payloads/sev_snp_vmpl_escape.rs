use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SevSnpVmplEscapePayload;

impl Payload for SevSnpVmplEscapePayload {
    fn name(&self) -> &str {
        "sev_snp_vmpl_escape"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x4000);
        let mut data = vec![0u8; size];

        // SEV-SNP VMSA (Virtual Machine Save Area) structure.
        // The detector keys on the binary VMSA signature followed by the
        // VMPL byte pair: [01 00 00 00 FE 53 4E 50] + vmpl + expected_vmpl.
        let vmsa_offset = 0x100;
        let vmsa_marker: [u8; 8] = [0x01, 0x00, 0x00, 0x00, 0xFE, 0x53, 0x4E, 0x50];
        data[vmsa_offset..vmsa_offset + vmsa_marker.len()].copy_from_slice(&vmsa_marker);
        // VMPL field: 0 (VMPL0 = hypervisor privilege)
        data[vmsa_offset + 8] = 0x00; // VMPL0
        // Expected VMPL: 2 (guest) — the confusion pair the detector matches
        data[vmsa_offset + 9] = 0x02;

        // SEV_FEATURES indicating VMPL2+ permissions (VmplSSS bit set)
        let sev_features: u64 = 0x0000_0000_0000_0004;
        data[vmsa_offset + 0x10..vmsa_offset + 0x18].copy_from_slice(&sev_features.to_le_bytes());

        // GHCB MSR protocol confusion
        let ghcb_offset = 0x400;
        let ghcb_marker = b"GHCB";
        data[ghcb_offset..ghcb_offset + ghcb_marker.len()].copy_from_slice(ghcb_marker);

        // GHCB MSR value with confused VMPL (protocol info says VMPL0, actual is VMPL2)
        let ghcb_msr: u64 = 0x0000_0000_0001_0014; // GHCBInfo=0x014 (SNP features), VMPL=0
        data[ghcb_offset + 8..ghcb_offset + 16].copy_from_slice(&ghcb_msr.to_le_bytes());

        // SNP_GUEST_REQUEST with escalated VMPL (detector keys on the
        // "SNP_GUEST_REQ" marker with VMPL byte at marker+4)
        let guest_req_offset = 0x800;
        let snp_req_marker = b"SNP_GUEST_REQ";
        data[guest_req_offset..guest_req_offset + snp_req_marker.len()]
            .copy_from_slice(snp_req_marker);
        // VMPL = 0 (escalated from expected VMPL2)
        data[guest_req_offset + snp_req_marker.len() + 4] = 0x00;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "confidential_vm".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
