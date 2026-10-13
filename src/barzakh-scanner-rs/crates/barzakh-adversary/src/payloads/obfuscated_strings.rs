use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ObfuscatedStringsPayload;

impl Payload for ObfuscatedStringsPayload {
    fn name(&self) -> &str {
        "obfuscated_strings"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x800);
        let mut data = vec![0u8; size];

        // Installer stub marker
        let stub = b"installer stub v2.1\n";
        let end = stub.len().min(size);
        data[0..end].copy_from_slice(&stub[..end]);

        // Literal ASCII shellcode escape text (backslash-x sequences, not raw bytes)
        let shellcode_off = 0x80;
        let shellcode_str = b"shellcode=\\x48\\x31\\xc0\\x31\\xd2\\x0f\\x05\n";
        let end = (shellcode_off + shellcode_str.len()).min(size);
        data[shellcode_off..end].copy_from_slice(&shellcode_str[..end - shellcode_off]);

        // Decoder and key material
        let decode_off = 0x100;
        let decode_str = b"decode=FromBase64String\nkey=xor_key=0x37\n";
        let end = (decode_off + decode_str.len()).min(size);
        data[decode_off..end].copy_from_slice(&decode_str[..end - decode_off]);

        // Process injection API chain
        let inject_off = 0x160;
        let inject_str = b"inject: VirtualAllocEx + WriteProcessMemory\n";
        let end = (inject_off + inject_str.len()).min(size);
        data[inject_off..end].copy_from_slice(&inject_str[..end - inject_off]);

        // Base64-looking encoded run
        let b64_off = 0x1A0;
        let b64_str = b"c3NoZHIwMGtpdHNoaW5zaGVsbGNvZGVwYXlsb2FkZXhlY3V0ZWQ=\n";
        let end = (b64_off + b64_str.len()).min(size);
        data[b64_off..end].copy_from_slice(&b64_str[..end - b64_off]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "nlp_strings".to_string(),
            min_severity: Severity::Medium,
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn obfuscated_strings_markers_present() {
        let payload = ObfuscatedStringsPayload;
        let data = payload.generate(&PayloadConfig::default()).unwrap();
        assert!(contains(&data, b"installer stub v2.1\n"));
        // Literal ASCII backslash-x escape text, not raw shellcode bytes
        assert!(contains(
            &data,
            b"shellcode=\\x48\\x31\\xc0\\x31\\xd2\\x0f\\x05\n"
        ));
        assert!(contains(&data, b"decode=FromBase64String\n"));
        assert!(contains(&data, b"key=xor_key=0x37\n"));
        assert!(contains(
            &data,
            b"inject: VirtualAllocEx + WriteProcessMemory\n"
        ));
        assert!(contains(
            &data,
            b"c3NoZHIwMGtpdHNoaW5zaGVsbGNvZGVwYXlsb2FkZXhlY3V0ZWQ=\n"
        ));
    }
}
