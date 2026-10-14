use std::path::Path;

use crate::detector::{Detector, DetectorError, Finding, Severity};

/// Detects the CVE-2024-7344 class of Secure Boot bypasses: a *signed* UEFI
/// PE binary acting as a custom loader that maps an *unsigned* embedded PE
/// payload with hand-rolled parsing (never passing through
/// `LoadImage`/`StartImage`, so nothing is measured). The tell is structural:
/// a complete, unsigned child PE image inside a parent PE section that is
/// both writable and executable.
pub struct PeLoaderBypassDetector;

impl Default for PeLoaderBypassDetector {
    fn default() -> Self {
        Self::new()
    }
}

const MZ: [u8; 2] = [0x4D, 0x5A];
const PE_SIG: [u8; 4] = [0x50, 0x45, 0x00, 0x00];
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Parsed PE view of an image at a given offset, if structurally valid.
struct PeView<'a> {
    data: &'a [u8],
    base: usize,
    optional_off: usize,
    section_off: usize,
    section_count: usize,
}

impl<'a> PeView<'a> {
    /// Validate the MZ → PE\0\0 chain with bounded sanity checks.
    fn parse(data: &'a [u8], base: usize) -> Option<PeView<'a>> {
        if base + 0x40 > data.len() || data[base..base + 2] != MZ {
            return None;
        }
        let e_lfanew = u32::from_le_bytes(data[base + 0x3C..base + 0x40].try_into().ok()?) as usize;
        if !(0x40..=0x400).contains(&e_lfanew) || base + e_lfanew + 24 > data.len() {
            return None;
        }
        let pe_off = base + e_lfanew;
        if data[pe_off..pe_off + 4] != PE_SIG {
            return None;
        }
        let section_count =
            u16::from_le_bytes(data[pe_off + 6..pe_off + 8].try_into().ok()?) as usize;
        let optional_size =
            u16::from_le_bytes(data[pe_off + 20..pe_off + 22].try_into().ok()?) as usize;
        if section_count == 0 || section_count > 96 || optional_size < 0xF0 {
            return None;
        }
        let optional_off = pe_off + 24;
        let magic = u16::from_le_bytes(data[optional_off..optional_off + 2].try_into().ok()?);
        if magic != 0x020B && magic != 0x010B {
            return None;
        }
        let section_off = optional_off + optional_size;
        if section_off + section_count * 40 > data.len() {
            return None;
        }
        Some(PeView {
            data,
            base,
            optional_off,
            section_off,
            section_count,
        })
    }

    /// Certificate-table size (data directory index 4). Zero → unsigned.
    fn certificate_size(&self) -> u32 {
        // Data directories start at optional+112 for PE32+ (0xF0 header) and
        // optional+96 for PE32 (0xE0). Both have dir[4] within bounds here.
        let dd = self.optional_off
            + match u16::from_le_bytes(
                self.data[self.optional_off..self.optional_off + 2]
                    .try_into()
                    .unwrap(),
            ) {
                0x020B => 112,
                _ => 96,
            };
        let dir4 = dd + 4 * 8;
        if dir4 + 8 > self.data.len() {
            return 0;
        }
        u32::from_le_bytes(self.data[dir4 + 4..dir4 + 8].try_into().unwrap())
    }

    /// Iterate (section_raw_offset, section_raw_size, characteristics).
    fn sections(&self) -> impl Iterator<Item = (usize, usize, u32)> + '_ {
        (0..self.section_count).map(move |i| {
            let s = self.section_off + i * 40;
            let raw_size =
                u32::from_le_bytes(self.data[s + 16..s + 20].try_into().unwrap()) as usize;
            let raw_ptr =
                u32::from_le_bytes(self.data[s + 20..s + 24].try_into().unwrap()) as usize;
            let chars = u32::from_le_bytes(self.data[s + 36..s + 40].try_into().unwrap());
            (raw_ptr, raw_size, chars)
        })
    }
}

impl PeLoaderBypassDetector {
    pub fn new() -> Self {
        Self
    }

    fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut findings = Vec::new();
        for base in find_pe_bases(data) {
            let Some(parent) = PeView::parse(data, base) else {
                continue;
            };
            for (raw_ptr, raw_size, chars) in parent.sections() {
                // A custom loader needs a writable+executable mapping for the
                // payload it copies in.
                if chars & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
                    != (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
                {
                    continue;
                }
                let start = base + raw_ptr;
                let end = (start + raw_size).min(data.len());
                if start >= end || raw_size < 0x100 {
                    continue;
                }
                // Look for a complete unsigned child PE inside the section.
                let section = &data[start..end];
                for j in 0..section.len().saturating_sub(2) {
                    if section[j..j + 2] == MZ {
                        let Some(child) = PeView::parse(data, start + j) else {
                            continue;
                        };
                        // The child must be fully contained in the parent
                        // section — an *embedded* payload, not an adjacent PE.
                        let child_end = child.section_off + child.section_count * 40;
                        if child_end > end - start {
                            continue;
                        }
                        if child.certificate_size() > 0 {
                            continue; // signed child — not this pattern
                        }
                        let child_wx = child.sections().any(|(_, _, c)| {
                            c & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
                                == (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)
                        });
                        if !child_wx {
                            continue;
                        }
                        findings.push(
                            Finding::new(
                                "pe_loader_bypass",
                                Severity::Critical,
                                "Signed loader mapping unsigned PE payload (CVE-2024-7344 class)",
                                &format!(
                                    "A signed-looking PE image at offset 0x{:08X} contains a \
                                     writable+executable section (0x{:X} bytes at raw offset \
                                     0x{:X}) holding a complete but UNSIGNED child PE image at \
                                     offset 0x{:08X}. The child has a zero certificate table \
                                     and its own writable+executable sections — the structure \
                                     of a custom loader that maps an unsigned payload without \
                                     passing through LoadImage/StartImage, so the load is \
                                     never measured and Secure Boot never evaluates it.",
                                    parent.base,
                                    raw_size,
                                    raw_ptr,
                                    start + j,
                                ),
                            )
                            .with_confidence(0.80)
                            .with_details(serde_json::json!({
                                "parent_offset": format!("0x{:08X}", parent.base),
                                "child_offset": format!("0x{:08X}", start + j),
                                "section_raw_size": raw_size,
                                "child_certificate_size": 0,
                            }))
                            .with_recommendation(
                                "Revoke the loader binary in dbx, re-image the firmware from \
                                 vendor media, and verify the TCG event log shows LoadImage \
                                 measurements for every boot-time driver.",
                            ),
                        );
                        break; // one finding per parent section is enough
                    }
                }
            }
        }
        findings
    }
}

/// Offsets of structurally valid PE images in the buffer.
fn find_pe_bases(data: &[u8]) -> Vec<usize> {
    let mut bases = Vec::new();
    for i in 0..data.len().saturating_sub(0x40) {
        if data[i..i + 2] == MZ && PeView::parse(data, i).is_some() {
            bases.push(i);
        }
    }
    bases
}

impl Detector for PeLoaderBypassDetector {
    fn name(&self) -> &str {
        "pe_loader_bypass"
    }

    fn detect(&self, target_path: &Path) -> Result<Vec<Finding>, DetectorError> {
        let data = std::fs::read(target_path).map_err(DetectorError::Io)?;
        Ok(self.scan(&data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal PE image with `sections` entries of (name, chars, raw content).
    fn build_pe(sections: &[(u32, Vec<u8>)], cert_size: u32) -> Vec<u8> {
        let header_len = 0x200;
        let total = header_len + sections.iter().map(|(_, c)| c.len()).sum::<usize>();
        let mut pe = vec![0u8; total];
        pe[0..2].copy_from_slice(&MZ);
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew
        let pe_off = 0x80;
        pe[pe_off..pe_off + 4].copy_from_slice(&PE_SIG);
        pe[pe_off + 6..pe_off + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes()); // NumberOfSections
        pe[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
        let optional = pe_off + 24;
        pe[optional..optional + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
                                                                              // Data directory 4 (security): virtual size ignored, raw size = cert_size.
        let dd = optional + 112 + 4 * 8;
        pe[dd + 4..dd + 8].copy_from_slice(&cert_size.to_le_bytes());
        // Section headers.
        let section_off = optional + 0xF0;
        let mut raw = header_len;
        for (i, (chars, content)) in sections.iter().enumerate() {
            let s = section_off + i * 40;
            pe[s..s + 8].copy_from_slice(b".payload");
            pe[s + 16..s + 20].copy_from_slice(&(content.len() as u32).to_le_bytes());
            pe[s + 20..s + 24].copy_from_slice(&(raw as u32).to_le_bytes());
            pe[s + 36..s + 40].copy_from_slice(&chars.to_le_bytes());
            pe[raw..raw + content.len()].copy_from_slice(content);
            raw += content.len();
        }
        pe
    }

    #[test]
    fn fires_on_signed_loader_with_unsigned_child() {
        let child = build_pe(
            &[(
                IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
                vec![0xCC; 0x200],
            )],
            0,
        );
        let parent = build_pe(
            &[(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE, child)],
            0x280, // parent pretends to carry a certificate
        );
        let findings = PeLoaderBypassDetector::new().scan(&parent);
        assert!(
            findings.iter().any(|f| f.severity == Severity::Critical),
            "expected loader-bypass finding: {findings:?}"
        );
    }

    #[test]
    fn quiet_on_signed_child() {
        let child = build_pe(&[(IMAGE_SCN_MEM_EXECUTE, vec![0xCC; 0x200])], 0x100);
        let parent = build_pe(
            &[(IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE, child)],
            0x280,
        );
        // Child has a certificate → not an unsigned-payload mapping.
        assert!(PeLoaderBypassDetector::new().scan(&parent).is_empty());
    }

    #[test]
    fn quiet_on_clean_buffer() {
        assert!(PeLoaderBypassDetector::new()
            .scan(&vec![0u8; 0x8000])
            .is_empty());
    }
}
