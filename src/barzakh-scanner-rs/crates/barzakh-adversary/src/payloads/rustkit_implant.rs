use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

/// RustKit marker GUID (matches `src/RustKitPkg/src/lib.rs` and the
/// `rust_uefi_module` detector):
/// 9B6E5C58-8C1E-4E5F-B07A-2D3C4F5E6A7B.
const RUSTKIT_MARKER_GUID: [u8; 16] = [
    0x58, 0x5C, 0x6E, 0x9B, 0x1E, 0x8C, 0x5F, 0x4E, 0xB0, 0x7A, 0x2D, 0x3C, 0x4F, 0x5E, 0x6A, 0x7B,
];

const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Emits firmware modeling an **unsigned Rust-compiled UEFI implant**: a
/// PE image carrying the Rust compiler path string (`/rustc/…`, embedded
/// in every Rust binary's panic metadata), the RustKit marker GUID in a
/// writable+executable section, and a zero certificate table. This is the
/// offense side of the Patina-era threat model: Rust firmware modules
/// whose C↔Rust FFI seams carry confused-deputy risk that signature
/// coverage does not address — and this one carries no signature at all.
pub struct RustkitImplantPayload;

impl Payload for RustkitImplantPayload {
    fn name(&self) -> &str {
        "rustkit_implant"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // PE image at offset 0.
        data[0..2].copy_from_slice(b"MZ");
        data[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        let pe_off = 0x80;
        data[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        data[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes()); // sections
        data[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes());
        let optional = pe_off + 24;
        data[optional..optional + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
                                                                                // Security directory (index 4): zero → unsigned.
        let dd = optional + 112 + 4 * 8;
        data[dd + 4..dd + 8].copy_from_slice(&0u32.to_le_bytes());
        // Section header: writable+executable payload section.
        let section_off = optional + 0xF0;
        data[section_off..section_off + 8].copy_from_slice(b".payload");
        data[section_off + 16..section_off + 20].copy_from_slice(&0x800u32.to_le_bytes());
        data[section_off + 20..section_off + 24].copy_from_slice(&0x200u32.to_le_bytes());
        data[section_off + 36..section_off + 40]
            .copy_from_slice(&(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE).to_le_bytes());

        // Section content: compiler path string + marker GUID + "FFI seam"
        // strings, the recognizable surface of a Rust UEFI binary.
        let sect = &mut data[0x200..0xA00];
        put(b"/rustc/9b3d25b16a1e9f2b4d3e", &mut sect[0x00..0x20]);
        sect[0x40..0x50].copy_from_slice(&RUSTKIT_MARKER_GUID);
        put(b"rustkit::dxe::efi_main", &mut sect[0x60..0x80]);
        put(b"commbuffer::validate_vulnerable", &mut sect[0x80..0xA0]);

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "rust_uefi_module".to_string(),
            min_severity: Severity::High,
        }]
    }
}

/// Copy `s` into `dest` (padded with zeros), tolerating length mismatch.
fn put(s: &[u8], dest: &mut [u8]) {
    let n = s.len().min(dest.len());
    dest[..n].copy_from_slice(&s[..n]);
}
