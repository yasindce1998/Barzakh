//! Minimal UEFI application wrapper: packs an adversary payload into a
//! valid x64 PE/COFF EFI application whose entry stub simply returns
//! EFI_SUCCESS. This is the deployment vehicle the cyber range uses for
//! removable-media droppers: the firmware's boot manager LoadImage()s
//! the whole file into guest RAM (reading every section), StartImage()s
//! the stub, and the implant bytes land in boot-time memory — exactly
//! the in-memory footprint a bootkit scanner has to find.

use anyhow::Result;

const OPT_HDR_SIZE: usize = 240; // PE32+ optional header
const COFF_HDR_SIZE: usize = 20;
const DOS_HDR_SIZE: usize = 64;
const FILE_ALIGNMENT: usize = 0x200;
const SECTION_ALIGNMENT: u32 = 0x1000;
const SECTION_RVA: u32 = 0x1000;
const HEADERS_SIZE: usize = 0x200;
const IMAGE_BASE: u64 = 0;
const SUBSYSTEM_EFI_APPLICATION: u16 = 10;
const MACHINE_X64: u16 = 0x8664;

/// x64 stub: `xor eax, eax; ret` — returns EFI_SUCCESS immediately.
const ENTRY_STUB: [u8; 3] = [0x31, 0xC0, 0xC3];

/// Wrap `payload` in a minimal UEFI application image.
pub fn wrap_payload_as_efi_app(payload: &[u8]) -> Result<Vec<u8>> {
    let section_raw = ENTRY_STUB
        .iter()
        .chain(payload.iter())
        .cloned()
        .collect::<Vec<u8>>();
    let size_of_raw_data = align_up_usize(section_raw.len(), FILE_ALIGNMENT);
    let virtual_size = section_raw.len() as u32;
    let size_of_image = SECTION_RVA + align_up(virtual_size, SECTION_ALIGNMENT);

    let mut image = vec![0u8; HEADERS_SIZE + size_of_raw_data];

    // DOS header.
    image[0] = b'M';
    image[1] = b'Z';
    let pe_offset = DOS_HDR_SIZE as u32;
    image[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

    // PE signature.
    let mut o = DOS_HDR_SIZE;
    image[o..o + 4].copy_from_slice(b"PE\0\0");
    o += 4;

    // COFF header.
    image[o..o + 2].copy_from_slice(&MACHINE_X64.to_le_bytes());
    image[o + 2..o + 4].copy_from_slice(&1u16.to_le_bytes()); // sections
    image[o + 4..o + 8].copy_from_slice(&0u32.to_le_bytes()); // timestamp
    image[o + 8..o + 16].copy_from_slice(&0u32.to_le_bytes().repeat(2)); // symbols
    image[o + 16..o + 18].copy_from_slice(&(OPT_HDR_SIZE as u16).to_le_bytes());
    image[o + 18..o + 20].copy_from_slice(&0x0022u16.to_le_bytes()); // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    o += COFF_HDR_SIZE;

    // Optional header (PE32+).
    let opt = o;
    image[opt..opt + 2].copy_from_slice(&0x020Bu16.to_le_bytes()); // PE32+ magic
    image[opt + 2] = 14; // linker version
    image[opt + 4..opt + 8].copy_from_slice(&(size_of_raw_data as u32).to_le_bytes()); // size of code
    image[opt + 16..opt + 20].copy_from_slice(&SECTION_RVA.to_le_bytes()); // entry RVA
    image[opt + 20..opt + 24].copy_from_slice(&SECTION_RVA.to_le_bytes()); // base of code
    image[opt + 24..opt + 32].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    image[opt + 32..opt + 36].copy_from_slice(&SECTION_ALIGNMENT.to_le_bytes());
    image[opt + 36..opt + 40].copy_from_slice(&(FILE_ALIGNMENT as u32).to_le_bytes());
    // OS/image versions (offsets 40..56).
    image[opt + 56..opt + 60].copy_from_slice(&size_of_image.to_le_bytes());
    image[opt + 60..opt + 64].copy_from_slice(&(HEADERS_SIZE as u32).to_le_bytes());
    image[opt + 68..opt + 70].copy_from_slice(&SUBSYSTEM_EFI_APPLICATION.to_le_bytes());
    // Stack/heap reserves (offsets 88..112) stay zero — fine for an app
    // that returns immediately.
    image[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // #data dirs
                                                                       // 16 empty data directories complete the optional header.
    o += OPT_HDR_SIZE;

    // Section header: ".fsh" — code + implant data, executable+readable.
    image[o..o + 8].copy_from_slice(b".fsh\0\0\0\0");
    image[o + 8..o + 12].copy_from_slice(&virtual_size.to_le_bytes());
    image[o + 12..o + 16].copy_from_slice(&SECTION_RVA.to_le_bytes());
    image[o + 16..o + 20].copy_from_slice(&(size_of_raw_data as u32).to_le_bytes());
    image[o + 20..o + 24].copy_from_slice(&(HEADERS_SIZE as u32).to_le_bytes()); // raw data ptr
    image[o + 36..o + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());

    // Section raw data: entry stub + implant bytes.
    let data = &mut image[HEADERS_SIZE..];
    data[..ENTRY_STUB.len()].copy_from_slice(&ENTRY_STUB);
    data[ENTRY_STUB.len()..ENTRY_STUB.len() + payload.len()].copy_from_slice(payload);

    Ok(image)
}

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

fn align_up_usize(value: usize, alignment: usize) -> usize {
    (value + alignment - 1) & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wraps_payload_in_valid_pe() {
        let payload = vec![0xAA; 0x1234];
        let image = wrap_payload_as_efi_app(&payload).unwrap();

        assert_eq!(&image[0..2], b"MZ");
        let pe_off = u32::from_le_bytes(image[0x3C..0x40].try_into().unwrap()) as usize;
        assert_eq!(&image[pe_off..pe_off + 4], b"PE\0\0");

        let machine = u16::from_le_bytes(image[pe_off + 4..pe_off + 6].try_into().unwrap());
        assert_eq!(machine, 0x8664);
        let opt_size = u16::from_le_bytes(image[pe_off + 20..pe_off + 22].try_into().unwrap());
        assert_eq!(opt_size as usize, OPT_HDR_SIZE);

        let opt = pe_off + 4 + COFF_HDR_SIZE;
        let magic = u16::from_le_bytes(image[opt..opt + 2].try_into().unwrap());
        assert_eq!(magic, 0x020B);
        let subsystem = u16::from_le_bytes(image[opt + 68..opt + 70].try_into().unwrap());
        assert_eq!(subsystem, SUBSYSTEM_EFI_APPLICATION);
        let entry = u32::from_le_bytes(image[opt + 16..opt + 20].try_into().unwrap());
        let size_of_image = u32::from_le_bytes(image[opt + 56..opt + 60].try_into().unwrap());
        let size_of_headers = u32::from_le_bytes(image[opt + 60..opt + 64].try_into().unwrap());
        assert_eq!(entry, SECTION_RVA);
        assert!(size_of_image > SECTION_RVA);
        assert_eq!(size_of_headers as usize, HEADERS_SIZE);

        // The section contains the stub followed by the payload.
        assert_eq!(&image[HEADERS_SIZE..HEADERS_SIZE + 3], &ENTRY_STUB);
        assert_eq!(
            &image[HEADERS_SIZE + 3..HEADERS_SIZE + 3 + payload.len()],
            &payload[..]
        );

        // File size is a multiple of the file alignment.
        assert_eq!(image.len() % FILE_ALIGNMENT, 0);
    }

    #[test]
    fn aligns_to_file_and_section_boundaries() {
        assert_eq!(align_up_usize(1, 0x200), 0x200);
        assert_eq!(align_up_usize(0x200, 0x200), 0x200);
        assert_eq!(align_up(0x1234, 0x1000), 0x2000);
    }
}
