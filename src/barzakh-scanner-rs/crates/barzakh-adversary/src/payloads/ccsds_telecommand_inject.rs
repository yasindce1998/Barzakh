use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct CcsdsTelecommandInjectPayload;

impl Payload for CcsdsTelecommandInjectPayload {
    fn name(&self) -> &str {
        "ccsds_telecommand_inject"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // CCSDS telecommand processor marker
        data[0..20].copy_from_slice(b"CCSDS TC_FRAME SDLS\x00");

        // SDLS authentication bypass
        let auth_off = 0x80;
        let auth_str = b"disable_sdls=1\nskip_tc_auth=true\nclear_key=session_key_0\n";
        let end = (auth_off + auth_str.len()).min(size);
        data[auth_off..end].copy_from_slice(&auth_str[..end - auth_off]);

        // Protocol manipulation
        let proto_off = 0x140;
        let proto_str = b"inject_tc_packet=armed\nbypass_cop1=sequence_override\n";
        let end = (proto_off + proto_str.len()).min(size);
        data[proto_off..end].copy_from_slice(&proto_str[..end - proto_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "ccsds_telecommand".to_string(),
            min_severity: Severity::Critical,
        }]
    }
}
