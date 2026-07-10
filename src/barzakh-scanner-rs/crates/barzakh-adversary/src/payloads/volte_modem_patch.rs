use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct VolteModemPatchPayload;

impl Payload for VolteModemPatchPayload {
    fn name(&self) -> &str {
        "volte_modem_patch"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x1000);
        let mut data = vec![0u8; size];

        // VoLTE DSP marker
        data[0..12].copy_from_slice(b"VoLTE_DSP_FW");

        // Embedded ELF binary (implant hidden inside DSP firmware)
        let elf_off = 0x200;
        // ELF magic
        data[elf_off] = 0x7F;
        data[elf_off + 1] = b'E';
        data[elf_off + 2] = b'L';
        data[elf_off + 3] = b'F';
        data[elf_off + 4] = 0x01; // 32-bit
        data[elf_off + 5] = 0x01; // little endian
        data[elf_off + 6] = 0x01; // ELF version

        // Fill ELF-like content
        for (j, byte) in data[elf_off + 7..(elf_off + 128).min(size)]
            .iter_mut()
            .enumerate()
        {
            *byte = (((elf_off + 7 + j) * 17 + 11) & 0xFF) as u8;
        }

        // Codec path interception hook
        let hook_off = 0x400;
        let hook_str = b"codec_hook=amr_wb\npcm_tap=enabled\nrecord_path=/data/voice/\n";
        let end = (hook_off + hook_str.len()).min(size);
        data[hook_off..end].copy_from_slice(&hook_str[..end - hook_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "volte_firmware".to_string(),
            min_severity: Severity::High,
        }]
    }
}
