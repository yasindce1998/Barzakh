//! Bounded TCG 1.2 / crypto-agile TPM 2.0 event log parser.
//! Parsing is not attestation: the log must still be bound to a trusted TPM
//! quote before treating it as cryptographic evidence.
use crate::detector::DetectorError;

#[derive(Debug, Clone)]
pub struct VariableMeasurement {
    pub offset: usize,
    pub guid: [u8; 16],
    pub name: String,
    pub data: Vec<u8>,
}

fn take<'a>(data: &'a [u8], pos: &mut usize, len: usize) -> Result<&'a [u8], DetectorError> {
    let end = pos
        .checked_add(len)
        .ok_or_else(|| DetectorError::Parse("TCG length overflow".into()))?;
    let bytes = data
        .get(*pos..end)
        .ok_or_else(|| DetectorError::Parse("truncated TCG event".into()))?;
    *pos = end;
    Ok(bytes)
}
fn u32_at(data: &[u8], pos: &mut usize) -> Result<u32, DetectorError> {
    Ok(u32::from_le_bytes(take(data, pos, 4)?.try_into().unwrap()))
}

pub fn variable_measurements(data: &[u8]) -> Result<Vec<VariableMeasurement>, DetectorError> {
    if data.is_empty() {
        return Err(DetectorError::Parse("empty TCG log".into()));
    }
    let mut pos = 0;
    let mut algorithms = std::collections::HashMap::new();
    let mut agile = false;
    let mut out = Vec::new();
    while pos < data.len() {
        let offset = pos;
        let pcr = u32_at(data, &mut pos)?;
        let event_type = u32_at(data, &mut pos)?;
        if pcr >= 24 {
            return Err(DetectorError::Parse("invalid PCR index".into()));
        }
        if agile {
            let count = u32_at(data, &mut pos)?;
            if count == 0 || count > 16 {
                return Err(DetectorError::Parse("invalid digest count".into()));
            }
            let mut seen = std::collections::HashSet::new();
            for _ in 0..count {
                let algorithm = u16::from_le_bytes(take(data, &mut pos, 2)?.try_into().unwrap());
                if !seen.insert(algorithm) {
                    return Err(DetectorError::Parse("duplicate digest algorithm".into()));
                }
                let size = *algorithms
                    .get(&algorithm)
                    .ok_or_else(|| DetectorError::Parse("undeclared digest algorithm".into()))?;
                take(data, &mut pos, size)?;
            }
        } else {
            take(data, &mut pos, 20)?;
        }
        let size = u32_at(data, &mut pos)? as usize;
        let event = take(data, &mut pos, size)?;
        if offset == 0 && event_type == 3 && event.starts_with(b"Spec ID Event03\0") {
            let mut cursor = 24;
            let count = u32_at(event, &mut cursor)?;
            if count == 0 || count > 16 {
                return Err(DetectorError::Parse(
                    "invalid SpecID algorithm count".into(),
                ));
            }
            for _ in 0..count {
                let id = u16::from_le_bytes(take(event, &mut cursor, 2)?.try_into().unwrap());
                let size =
                    u16::from_le_bytes(take(event, &mut cursor, 2)?.try_into().unwrap()) as usize;
                let expected = match id {
                    4 => 20,
                    11 => 32,
                    12 => 48,
                    13 => 64,
                    _ => size,
                };
                if size == 0
                    || size > 64
                    || size != expected
                    || algorithms.insert(id, size).is_some()
                {
                    return Err(DetectorError::Parse(
                        "invalid SpecID digest size/algorithm".into(),
                    ));
                }
            }
            let vendor_len = take(event, &mut cursor, 1)?[0] as usize;
            take(event, &mut cursor, vendor_len)?;
            if cursor != event.len() {
                return Err(DetectorError::Parse("trailing SpecID data".into()));
            }
            agile = true;
        }
        // EV_EFI_VARIABLE_DRIVER_CONFIG measures policy state into PCR7.
        // EV_EFI_VARIABLE_AUTHORITY is authorization evidence, not state.
        if pcr == 7 && event_type == 0x8000_0001 {
            let mut cursor = 0;
            let guid = take(event, &mut cursor, 16)?.try_into().unwrap();
            let name_len = u64::from_le_bytes(take(event, &mut cursor, 8)?.try_into().unwrap());
            let data_len = u64::from_le_bytes(take(event, &mut cursor, 8)?.try_into().unwrap());
            let name_bytes = usize::try_from(name_len)
                .ok()
                .and_then(|n| n.checked_mul(2))
                .ok_or_else(|| DetectorError::Parse("variable name too large".into()))?;
            if name_bytes > 2048 {
                return Err(DetectorError::Parse("variable name too large".into()));
            }
            let name: Vec<u16> = take(event, &mut cursor, name_bytes)?
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let name = String::from_utf16(&name)
                .map_err(|_| DetectorError::Parse("invalid variable name".into()))?;
            let data_len = usize::try_from(data_len)
                .map_err(|_| DetectorError::Parse("variable data too large".into()))?;
            let value = take(event, &mut cursor, data_len)?.to_vec();
            if cursor != event.len() {
                return Err(DetectorError::Parse("trailing variable event data".into()));
            }
            out.push(VariableMeasurement {
                offset,
                guid,
                name: name.trim_end_matches('\0').into(),
                data: value,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_crypto_agile_log_and_rejects_bad_algorithm_declarations() {
        let mut spec = b"Spec ID Event03\0".to_vec();
        spec.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 2]); // platform/version/uintn
        spec.extend_from_slice(&1u32.to_le_bytes());
        spec.extend_from_slice(&11u16.to_le_bytes());
        spec.extend_from_slice(&32u16.to_le_bytes());
        spec.push(0); // no vendor data
        let mut log = 0u32.to_le_bytes().to_vec();
        log.extend_from_slice(&3u32.to_le_bytes());
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&(spec.len() as u32).to_le_bytes());
        log.extend_from_slice(&spec);
        log.extend_from_slice(&7u32.to_le_bytes());
        log.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        log.extend_from_slice(&1u32.to_le_bytes());
        log.extend_from_slice(&11u16.to_le_bytes());
        log.extend_from_slice(&[0; 32]);
        let mut event = vec![0; 16];
        event.extend_from_slice(&2u64.to_le_bytes());
        event.extend_from_slice(&1u64.to_le_bytes());
        event.extend_from_slice(b"d\0b\0");
        event.push(42);
        log.extend_from_slice(&(event.len() as u32).to_le_bytes());
        log.extend(event);
        let result = variable_measurements(&log).unwrap();
        assert_eq!(result[0].data, [42]);
        // SHA256 digest size in SpecID must be exactly 32.
        log[32 + 30] = 31;
        assert!(variable_measurements(&log).is_err());
    }
    #[test]
    fn rejects_truncated_and_marker_only_logs() {
        for n in 0..32 {
            assert!(variable_measurements(&vec![0; n]).is_err());
        }
        assert!(variable_measurements(&0x8000_0001u32.to_le_bytes()).is_err());
    }
    #[test]
    fn parses_policy_variable() {
        let mut event = vec![0u8; 16];
        event.extend_from_slice(&2u64.to_le_bytes());
        event.extend_from_slice(&1u64.to_le_bytes());
        event.extend_from_slice(b"d\0b\0");
        event.push(42);
        let mut log = 7u32.to_le_bytes().to_vec();
        log.extend_from_slice(&0x8000_0001u32.to_le_bytes());
        log.extend_from_slice(&[0; 20]);
        log.extend_from_slice(&(event.len() as u32).to_le_bytes());
        log.extend(event);
        let measurements = variable_measurements(&log).unwrap();
        assert_eq!(measurements[0].name, "db");
        assert_eq!(measurements[0].data, [42]);
        log.pop();
        assert!(variable_measurements(&log).is_err());
    }
}
