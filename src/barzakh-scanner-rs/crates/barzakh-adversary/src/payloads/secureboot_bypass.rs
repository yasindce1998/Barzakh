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

        // At offset 0x000: SecureBoot variable GUID {8be4df61-93ca-11d2-aa0d-00e098032b8c}
        // followed by variable value 0x00 (SecureBoot DISABLED)
        let offset = 0x000;
        let secureboot_guid: [u8; 16] = [
            0x61, 0xDF, 0xE4, 0x8B, // Data1 LE
            0xCA, 0x93, // Data2 LE
            0xD2, 0x11, // Data3 LE
            0xAA, 0x0D, // Data4[0..2]
            0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C, // Data4[2..8]
        ];
        data[offset..offset + 16].copy_from_slice(&secureboot_guid);
        // SecureBoot value = 0x00 (DISABLED)
        data[offset + 16] = 0x00;

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
