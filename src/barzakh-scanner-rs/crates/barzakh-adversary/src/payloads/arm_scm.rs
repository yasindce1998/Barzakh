use anyhow::Result;
use byteorder::{LittleEndian, WriteBytesExt};

use crate::{Arch, ExpectedFinding, Payload, PayloadConfig};
use barzakh_core::Severity;

pub struct ArmScmPayload;

impl Payload for ArmScmPayload {
    fn name(&self) -> &str {
        "arm_scm"
    }

    fn arch(&self) -> Arch {
        Arch::Aarch64
    }

    fn generate(&self, config: &PayloadConfig) -> Result<Vec<u8>> {
        let size = config.size.max(0x2000);
        let mut data = vec![0u8; size];

        // Qualcomm SCM (Secure Channel Manager) call injection pattern
        // SCM calls use SMC #0 with specific register conventions:
        //   x0 = service ID | command ID
        //   x1 = argument count
        //   x2..x5 = arguments
        // Note: the detector reads the service ID from the last MOVZ before
        // the SMC, so MOV X0 must directly precede SMC #0 in each block.

        // First SCM call: PIL (Peripheral Image Loader) service abuse
        // Service 0x04 (PIL), Command 0x02 (init_image) — loads unsigned image
        let offset = 0x100;
        // MOV X1, #3 (3 arguments)
        let mut cursor = std::io::Cursor::new(&mut data[offset..offset + 4]);
        cursor.write_u32::<LittleEndian>(0xD280_0061)?;
        // LDR X2, [SP, #0x10] — load peripheral ID from stack
        let mut cursor = std::io::Cursor::new(&mut data[offset + 4..offset + 8]);
        cursor.write_u32::<LittleEndian>(0xF940_0BE2)?;
        // MOV X0, #0x0402 (service=PIL, cmd=init_image)
        let mut cursor = std::io::Cursor::new(&mut data[offset + 8..offset + 12]);
        cursor.write_u32::<LittleEndian>(0xD280_8040)?;
        // SMC #0
        let mut cursor = std::io::Cursor::new(&mut data[offset + 12..offset + 16]);
        cursor.write_u32::<LittleEndian>(0xD400_0003)?;

        // Second SCM call: TZ App loader (loads arbitrary trustlet)
        // Service 0x01 (TZ), Command 0x01 (load_app)
        let offset2 = 0x200;
        // MOV X1, #2
        let mut cursor = std::io::Cursor::new(&mut data[offset2..offset2 + 4]);
        cursor.write_u32::<LittleEndian>(0xD280_0041)?;
        // LDR X2, [X19] — app buffer address from controlled pointer
        let mut cursor = std::io::Cursor::new(&mut data[offset2 + 4..offset2 + 8]);
        cursor.write_u32::<LittleEndian>(0xF940_0262)?;
        // MOV X0, #0x0101
        let mut cursor = std::io::Cursor::new(&mut data[offset2 + 8..offset2 + 12]);
        cursor.write_u32::<LittleEndian>(0xD280_2020)?;
        // SMC #0
        let mut cursor = std::io::Cursor::new(&mut data[offset2 + 12..offset2 + 16]);
        cursor.write_u32::<LittleEndian>(0xD400_0003)?;

        // Third SCM call: direct memory write via QFPROM (fuse) service
        // Service 0x05 (FUSE), Command 0x01 (write_row) — writes OEM fuse values
        let offset3 = 0x300;
        // MOV X1, #4
        let mut cursor = std::io::Cursor::new(&mut data[offset3..offset3 + 4]);
        cursor.write_u32::<LittleEndian>(0xD280_0081)?;
        // MOV X0, #0x0501
        let mut cursor = std::io::Cursor::new(&mut data[offset3 + 8..offset3 + 12]);
        cursor.write_u32::<LittleEndian>(0xD280_A020)?;
        // SMC #0
        let mut cursor = std::io::Cursor::new(&mut data[offset3 + 12..offset3 + 16]);
        cursor.write_u32::<LittleEndian>(0xD400_0003)?;

        Ok(data)
    }

    fn expected_detections(&self) -> Vec<ExpectedFinding> {
        vec![ExpectedFinding {
            detector: "arm_trustzone".to_string(),
            min_severity: Severity::High,
        }]
    }
}
