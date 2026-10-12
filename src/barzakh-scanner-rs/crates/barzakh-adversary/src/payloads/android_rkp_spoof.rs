use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AndroidRkpSpoofPayload;

impl Payload for AndroidRkpSpoofPayload {
    fn name(&self) -> &str {
        "android_rkp_spoof"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // COSE_Key structure: map with key type EC2
        // CBOR map header (5 entries) + key type 2 (EC2)
        data[0] = 0xA5;
        data[1] = 0x01;
        data[2] = 0x02;

        // Key ID indicating non-Google EEK root
        // Instead of Google's production EEK, use a custom root
        let eek_offset = 0x20;
        let non_google_root = b"custom-eek-root-cert-authority";
        data[eek_offset..eek_offset + non_google_root.len()].copy_from_slice(non_google_root);

        // KeyMint HAL service name (used for CSR identification)
        let km_offset = 0x100;
        let km_service = b"google/keymint";
        data[km_offset..km_offset + km_service.len()].copy_from_slice(km_service);

        // CSR security level downgrade: set to SOFTWARE (0) instead of TRUSTED_ENVIRONMENT (1)
        // or STRONGBOX (2)
        let csr_offset = 0x200;
        data[csr_offset] = 0xA5; // CBOR map
        data[csr_offset + 1] = 0x01;
        data[csr_offset + 2] = 0x02;
        // Security level field = 0 (SOFTWARE) instead of expected TEE/StrongBox
        data[csr_offset + 8] = 0x00;

        // Factory test certificate bypass pattern (the detector requires
        // both "FactoryKeys" and "testcert" markers)
        let factory_offset = 0x300;
        let factory_marker = b"FactoryKeys";
        data[factory_offset..factory_offset + factory_marker.len()].copy_from_slice(factory_marker);
        let testcert_marker = b"testcert";
        let tc_offset = factory_offset + 20;
        data[tc_offset..tc_offset + testcert_marker.len()].copy_from_slice(testcert_marker);

        // Provisioning status: mark as test/factory to bypass RKP validation
        data[factory_offset + 16] = 0x01; // test mode flag

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "android_rkp".to_string(),
            min_severity: Severity::High,
        }]
    }
}
