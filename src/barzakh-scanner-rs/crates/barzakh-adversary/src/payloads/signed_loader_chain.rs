use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// Minimal PE image with the given sections (chars, raw content) and
/// certificate-table size. Mirrors the structures the `pe_loader_bypass`
/// detector validates: MZ header, PE\0\0 at e_lfanew, PE32+ optional header
/// with a data directory, and COFF section table.
struct PeBuilder {
    sections: Vec<(u32, Vec<u8>)>,
    cert_size: u32,
}

impl PeBuilder {
    fn build(&self) -> Vec<u8> {
        let header_len = 0x200;
        let total = header_len + self.sections.iter().map(|(_, c)| c.len()).sum::<usize>();
        let mut pe = vec![0u8; total];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        let pe_off = 0x80;
        pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        pe[pe_off + 6..pe_off + 8].copy_from_slice(&(self.sections.len() as u16).to_le_bytes());
        pe[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes());
        let optional = pe_off + 24;
        pe[optional..optional + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
        let dd = optional + 112 + 4 * 8; // data directory 4 (security)
        pe[dd + 4..dd + 8].copy_from_slice(&self.cert_size.to_le_bytes());
        let section_off = optional + 0xF0;
        let mut raw = header_len;
        for (i, (chars, content)) in self.sections.iter().enumerate() {
            let s = section_off + i * 40;
            pe[s..s + 8].copy_from_slice(b".image\0\0");
            pe[s + 16..s + 20].copy_from_slice(&(content.len() as u32).to_le_bytes());
            pe[s + 20..s + 24].copy_from_slice(&(raw as u32).to_le_bytes());
            pe[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
            pe[raw..raw + content.len()].copy_from_slice(content);
            raw += content.len();
        }
        pe
    }
}

/// Emits firmware modeling the CVE-2024-7344 class of Secure Boot bypass:
/// a *signed* UEFI PE binary acts as a custom loader, mapping an *unsigned*
/// embedded PE payload with hand-rolled parsing inside a writable+executable
/// section. The load bypasses `LoadImage`/`StartImage`, so nothing is
/// measured and Secure Boot never evaluates the payload.
pub struct SignedLoaderChainPayload;

impl Payload for SignedLoaderChainPayload {
    fn name(&self) -> &str {
        "signed_loader_chain"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Unsigned child PE: zero certificate table, writable+executable
        // section (the implant payload the loader maps).
        let child = PeBuilder {
            sections: vec![(0x8000_0000 | 0x2000_0000, vec![0xCC; 0x200])],
            cert_size: 0,
        }
        .build();

        // Signed parent PE: non-zero certificate table (it *looks* signed),
        // carrying the child in a writable+executable section.
        let parent = PeBuilder {
            sections: vec![(0x8000_0000 | 0x2000_0000, child)],
            cert_size: 0x280,
        }
        .build();

        data[..parent.len()].copy_from_slice(&parent);
        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "pe_loader_bypass".to_string(),
            min_severity: Severity::High,
        }]
    }
}
