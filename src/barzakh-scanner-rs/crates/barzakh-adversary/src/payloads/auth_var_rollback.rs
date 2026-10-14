use anyhow::Result;

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct AuthVarRollbackPayload;

impl Payload for AuthVarRollbackPayload {
    fn name(&self) -> &str {
        "auth_var_rollback"
    }

    fn arch(&self) -> Arch {
        Arch::X86_64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // EFI_IMAGE_SECURITY_DATABASE_GUID {d719b2cb-3d3a-4596-a3bc-dad00e67656f}
        let db_guid: [u8; 16] = [
            0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67,
            0x65, 0x6F,
        ];
        // EFI_GLOBAL_VARIABLE_GUID {8BE4DF61-93CA-11D2-AA0D-00E098032B8C}
        let global_guid: [u8; 16] = [
            0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03,
            0x2B, 0x8C,
        ];

        // Variable store header: gEfiAuthenticatedVariableGuid signature,
        // size, format (0x5A), state (0xFE = healthy).
        let varstore_guid: [u8; 16] = [
            0x98, 0x58, 0x4E, 0xEE, 0x14, 0x39, 0x59, 0x42, 0x9D, 0x6E, 0xDC, 0x7B, 0xD7, 0x94,
            0x03, 0xCF,
        ];
        data[0x000..0x010].copy_from_slice(&varstore_guid);
        let store_size: u32 = size as u32;
        data[0x010..0x014].copy_from_slice(&store_size.to_le_bytes());
        data[0x014] = 0x5A;
        data[0x015] = 0xFE;

        // Writes one EDK2 authenticated VARIABLE_HEADER entry at `off`
        // and returns the offset just past it (4-byte aligned).
        fn write_entry(
            data: &mut [u8],
            off: usize,
            guid: &[u8; 16],
            name: &str,
            attributes: u32,
            payload: &[u8],
        ) -> usize {
            let name_bytes: Vec<u8> = name
                .chars()
                .flat_map(|c| [(c as u16) as u8, ((c as u16) >> 8) as u8])
                .chain([0u8, 0u8]) // NUL terminator
                .collect();

            data[off] = 0x55; // StartId
            data[off + 1] = 0xAA;
            data[off + 2] = 0x3F; // State: VAR_ADDED
            data[off + 3] = 0x00; // Reserved
            data[off + 4..off + 8].copy_from_slice(&attributes.to_le_bytes());
            // MonotonicCount (+8, 8 bytes) and TimeStamp (+16, 16 bytes)
            // remain zero: monotonic counter 0 and a zeroed timestamp are
            // the rollback indicators. PubKeyIndex (+32) is zero.
            data[off + 36..off + 40].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
            data[off + 40..off + 44].copy_from_slice(&(payload.len() as u32).to_le_bytes());
            data[off + 44..off + 60].copy_from_slice(guid);
            data[off + 60..off + 60 + name_bytes.len()].copy_from_slice(&name_bytes);
            data[off + 60 + name_bytes.len()..off + 60 + name_bytes.len() + payload.len()]
                .copy_from_slice(payload);
            (off + 60 + name_bytes.len() + payload.len()).next_multiple_of(4)
        }

        // First variable: db without TIME_BASED_AUTHENTICATED_WRITE_ACCESS.
        // NV + BS + RT only — the security database can be modified
        // without cryptographic proof.
        let db_attrs: u32 = 0x01 | 0x02 | 0x04;
        let mut next = write_entry(&mut data, 0x040, &db_guid, "db", db_attrs, &[0xAA; 0x20]);

        // Second variable: PK claiming time-based authentication with an
        // all-zero timestamp (replay / rollback).
        let pk_attrs: u32 = 0x01 | 0x02 | 0x04 | 0x20;
        next = write_entry(&mut data, next, &global_guid, "PK", pk_attrs, &[0xBB; 0x20]);

        // Third variable: KEK with time-based auth, zeroed timestamp and
        // monotonic counter 0.
        let kek_attrs: u32 = 0x01 | 0x02 | 0x04 | 0x20 | 0x40;
        let _ = write_entry(
            &mut data,
            next,
            &global_guid,
            "KEK",
            kek_attrs,
            &[0xCC; 0x20],
        );

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "auth_variable".to_string(),
            min_severity: Severity::High,
        }]
    }
}
