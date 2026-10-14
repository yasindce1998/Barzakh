use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct SecurebootBypassPayload;

impl Payload for SecurebootBypassPayload {
    fn name(&self) -> &str {
        "secureboot_bypass"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // At offset 0x000: an EFI authenticated variable store whose
        // SecureBoot variable carries value 0x00 (DISABLED). This models
        // an attacker flipping the variable inside a dumped NVRAM store:
        // a real store header plus a well-formed variable entry.
        let store_offset = 0x000;
        // gEfiAuthenticatedVariableGuid {ee4e5898-3914-4259-9d6e-dc7bd79403cf}
        // (the variable store signature)
        let varstore_guid: [u8; 16] = [
            0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94,
            0x03, 0xCF,
        ];
        data[store_offset..store_offset + 16].copy_from_slice(&varstore_guid);
        // Store size, format (0x5A = formatted), state (0xFE = healthy)
        let store_size: u32 = 0x1000;
        data[store_offset + 16..store_offset + 20].copy_from_slice(&store_size.to_le_bytes());
        data[store_offset + 20] = 0x5A;
        data[store_offset + 21] = 0xFE;

        // Variable entry (EDK2 authenticated VARIABLE_HEADER) at 0x040
        let entry = 0x040;
        data[entry] = 0x55; // StartId
        data[entry + 1] = 0xAA;
        data[entry + 2] = 0x3F; // State: VAR_ADDED
        data[entry + 3] = 0x00; // Reserved
        let attrs: u32 = 0x01 | 0x02 | 0x04; // NON_VOLATILE | BOOTSERVICE | RUNTIME
        data[entry + 4..entry + 8].copy_from_slice(&attrs.to_le_bytes());
        // MonotonicCount (+8, 8 bytes), TimeStamp (+16, 16 bytes) and
        // PubKeyIndex (+32) are zero for a non-authenticated variable.
        // NameSize (+36), DataSize (+40):
        let secureboot_ucs2: [u8; 22] = [
            0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x75, 0x00, 0x72, 0x00, 0x65, 0x00, 0x42, 0x00,
            0x6F, 0x00, 0x6F, 0x00, 0x74, 0x00, 0x00, 0x00,
        ];
        data[entry + 36..entry + 40].copy_from_slice(&22u32.to_le_bytes());
        data[entry + 40..entry + 44].copy_from_slice(&1u32.to_le_bytes());
        // VendorGUID: EFI_GLOBAL_VARIABLE_GUID {8be4df61-93ca-11d2-aa0d-00e098032b8c}
        let secureboot_guid: [u8; 16] = [
            0x61, 0xDF, 0xE4, 0x8B, // Data1 LE
            0xCA, 0x93, // Data2 LE
            0xD2, 0x11, // Data3 LE
            0xAA, 0x0D, // Data4[0..2]
            0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C, // Data4[2..8]
        ];
        data[entry + 44..entry + 60].copy_from_slice(&secureboot_guid);
        // Variable name "SecureBoot" in UCS-2
        data[entry + 60..entry + 82].copy_from_slice(&secureboot_ucs2);
        // SecureBoot value = 0x00 (DISABLED)
        data[entry + 82] = 0x00;

        // At offset 0x100: EFI_SIGNATURE_LIST header
        // SignatureType GUID for X509: {a5c059a1-94e4-4aa7-87b5-ab155c2bf072}
        let offset = 0x100;
        let x509_guid: [u8; 16] = [
            0xA1, 0x59, 0xC0, 0xA5, // Data1 LE
            0xE4, 0x94, // Data2 LE
            0xA7, 0x4A, // Data3 LE
            0x87, 0xB5, // Data4[0..2]
            0xAB, 0x15, 0x5C, 0x2B, 0xF0, 0x72, // Data4[2..8]
        ];
        data[offset..offset + 16].copy_from_slice(&x509_guid);
        // SignatureListSize = 0x100
        let sig_list_size: u32 = 0x100;
        data[offset + 16..offset + 20].copy_from_slice(&sig_list_size.to_le_bytes());
        // SignatureHeaderSize = 0
        let sig_header_size: u32 = 0x00;
        data[offset + 20..offset + 24].copy_from_slice(&sig_header_size.to_le_bytes());
        // SignatureSize = 0xE0
        let sig_size: u32 = 0xE0;
        data[offset + 24..offset + 28].copy_from_slice(&sig_size.to_le_bytes());

        // At offset 0x200: SECOND EFI_SIGNATURE_LIST (anomalous — PK should have exactly 1)
        let offset = 0x200;
        data[offset..offset + 16].copy_from_slice(&x509_guid);
        data[offset + 16..offset + 20].copy_from_slice(&sig_list_size.to_le_bytes());
        data[offset + 20..offset + 24].copy_from_slice(&sig_header_size.to_le_bytes());
        data[offset + 24..offset + 28].copy_from_slice(&sig_size.to_le_bytes());

        // At offset 0x300: Minimal ASN.1 certificate stub with very short validity dates
        let offset = 0x300;
        // SEQUENCE tag
        data[offset] = 0x30;
        data[offset + 1] = 0x50; // length of sequence
                                 // TBSCertificate SEQUENCE
        data[offset + 2] = 0x30;
        data[offset + 3] = 0x40;
        // Version [0] EXPLICIT
        data[offset + 4] = 0xA0;
        data[offset + 5] = 0x03;
        data[offset + 6] = 0x02;
        data[offset + 7] = 0x01;
        data[offset + 8] = 0x02; // v3
                                 // Serial number
        data[offset + 9] = 0x02;
        data[offset + 10] = 0x01;
        data[offset + 11] = 0x01;
        // Skip to validity (at offset +0x20 for simplicity)
        // Validity SEQUENCE with very short dates
        data[offset + 0x20] = 0x30; // SEQUENCE
        data[offset + 0x21] = 0x1E; // length
                                    // notBefore: UTCTime "250101000000Z" (2025-01-01)
        data[offset + 0x22] = 0x17; // UTCTime tag
        data[offset + 0x23] = 0x0D; // length 13
        data[offset + 0x24..offset + 0x31].copy_from_slice(b"2501010000Z\x00\x00");
        // notAfter: UTCTime "250102000000Z" (2025-01-02, only 1 day validity!)
        data[offset + 0x31] = 0x17; // UTCTime tag
        data[offset + 0x32] = 0x0D; // length 13
        data[offset + 0x33..offset + 0x40].copy_from_slice(b"2501020000Z\x00\x00");

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "secureboot_chain".to_string(),
            min_severity: Severity::High,
        }]
    }
}
