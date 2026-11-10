//! Shared parser for EFI authenticated variable stores.
//!
//! Several detectors (Secure Boot state, authenticated-variable rollback)
//! need to reason about UEFI variables. Interpreting bare GUIDs or UTF-16
//! name strings found anywhere in an image produces false positives on
//! legitimate binaries that merely *reference* variables (every UEFI
//! application embeds `gEfiGlobalVariableGuid` and the strings
//! "SecureBoot"/"SetupMode"). Instead, variables are only parsed from
//! real variable-store entries: a formatted store header followed by
//! `VARIABLE_HEADER` records in the EDK2 authenticated format.

/// `gEfiAuthenticatedVariableGuid` (authenticated variable store signature).
pub(crate) const AUTH_VARSTORE_GUID: [u8; 16] = [
    0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94, 0x03, 0xCF,
];

/// `gEfiVariableGuid` (legacy variable store signature).
pub(crate) const STD_VARSTORE_GUID: [u8; 16] = [
    0x16, 0x36, 0xCF, 0xDD, 0x75, 0x32, 0x64, 0x42, 0x98, 0xB6, 0xFE, 0x85, 0x70, 0x7F, 0xFE, 0x7D,
];

/// `VAR_ADDED` state for a variable-store entry.
const VAR_ADDED: u8 = 0x3F;
/// Size of the authenticated `VARIABLE_HEADER` (before the name).
const VAR_HEADER_SIZE: usize = 60;
/// StartId marking the beginning of an entry.
const VAR_START_ID: [u8; 2] = [0x55, 0xAA];

/// One parsed variable-store entry.
pub(crate) struct VarEntry<'a> {
    /// File offset of the entry header.
    pub offset: usize,
    pub attributes: u32,
    pub timestamp: [u8; 16],
    pub guid: [u8; 16],
    /// Variable name decoded from UTF-16LE (ASCII subset).
    pub name: String,
    /// Variable payload.
    pub data: &'a [u8],
}

/// Returns true when `data` contains a formatted EFI variable-store header.
fn has_varstore_header(data: &[u8]) -> bool {
    data.windows(16).any(|w| w == AUTH_VARSTORE_GUID)
        || data.windows(16).any(|w| w == STD_VARSTORE_GUID)
}

/// Parses variable entries from an EFI authenticated variable store.
///
/// Requires a store header to be present anywhere in the image (a store
/// dump always begins with one) and only accepts well-formed entries:
/// `StartId` 0x55AA, `VAR_ADDED` state, sane sizes, and an ASCII UTF-16LE
/// name. Random byte sequences essentially never satisfy all of these.
pub(crate) fn parse_entries(data: &[u8]) -> Vec<VarEntry<'_>> {
    let mut entries = Vec::new();
    if data.len() < VAR_HEADER_SIZE + 4 || !has_varstore_header(data) {
        return entries;
    }

    let mut i = 0usize;
    while i + VAR_HEADER_SIZE + 4 <= data.len() {
        if data[i..i + 2] != VAR_START_ID || data[i + 2] != VAR_ADDED {
            i += 4; // entries are 4-byte aligned in the store
            continue;
        }

        let attributes = u32::from_le_bytes(data[i + 4..i + 8].try_into().unwrap_or([0; 4]));
        let mut timestamp = [0u8; 16];
        timestamp.copy_from_slice(&data[i + 16..i + 32]);
        let name_size = u32::from_le_bytes(data[i + 36..i + 40].try_into().unwrap_or([0; 4]));
        let data_size = u32::from_le_bytes(data[i + 40..i + 44].try_into().unwrap_or([0; 4]));

        let name_size = name_size as usize;
        let data_size = data_size as usize;
        let Some(end) = i
            .checked_add(VAR_HEADER_SIZE)
            .and_then(|v| v.checked_add(name_size))
            .and_then(|v| v.checked_add(data_size))
        else {
            break;
        };
        if !(2..=1024).contains(&name_size)
            || !name_size.is_multiple_of(2)
            || data_size > data.len()
            || end > data.len()
        {
            i += 4;
            continue;
        }

        // The name must be printable ASCII in UTF-16LE (UEFI variable
        // names are ASCII); this rejects noise that survives the
        // structural checks.
        let name_raw = &data[i + VAR_HEADER_SIZE..i + VAR_HEADER_SIZE + name_size];
        let mut chars: Vec<u8> = Vec::with_capacity(name_size / 2);
        let mut printable = true;
        for c in name_raw.chunks(2) {
            let u = u16::from_le_bytes([c[0], c[1]]);
            if u == 0 {
                break;
            }
            if !(0x20..0x7F).contains(&u) {
                printable = false;
                break;
            }
            chars.push(u as u8);
        }
        if !printable || chars.is_empty() {
            i += 4;
            continue;
        }

        let mut guid = [0u8; 16];
        guid.copy_from_slice(&data[i + 44..i + 60]);

        entries.push(VarEntry {
            offset: i,
            attributes,
            timestamp,
            guid,
            name: String::from_utf8_lossy(&chars).into_owned(),
            data: &data[i + VAR_HEADER_SIZE + name_size..end],
        });

        // Continue after this entry (aligned to 4 bytes like the store).
        i = end.next_multiple_of(4);
    }

    entries
}
