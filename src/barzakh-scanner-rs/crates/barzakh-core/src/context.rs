//! Immutable input shared by every detector in one scan.
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use sha2::{Digest, Sha256};

use crate::detector::DetectorError;

/// A bounded, owned snapshot avoids repeated reads and mmap mutation races.
/// The default limit accommodates firmware images; callers can opt into larger
/// memory dumps with [`ScanContext::load_with_limit`].
pub const DEFAULT_MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

pub struct ScanContext {
    path: PathBuf,
    data: Arc<Vec<u8>>,
    sha256: OnceLock<String>,
    measurements: Option<Vec<crate::tcg::VariableMeasurement>>,
    event_log_sha256: Option<String>,
}

impl ScanContext {
    pub fn load(path: &Path) -> Result<Self, DetectorError> {
        Self::load_with_limit(path, DEFAULT_MAX_IMAGE_BYTES)
    }

    pub fn load_with_limit(path: &Path, limit: u64) -> Result<Self, DetectorError> {
        let metadata = std::fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(DetectorError::Config(
                "target must be a regular file".into(),
            ));
        }
        if metadata.len() == 0 || metadata.len() > limit {
            return Err(DetectorError::Config(format!(
                "image size must be between 1 and {limit} bytes"
            )));
        }
        let file = std::fs::File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(DetectorError::Config(
                "target must be a regular file".into(),
            ));
        }
        let mut data = Vec::new();
        file.take(limit.saturating_add(1)).read_to_end(&mut data)?;
        if data.is_empty() || data.len() as u64 > limit {
            return Err(DetectorError::Config("invalid or oversized image".into()));
        }
        Ok(Self::from_bytes(path.to_path_buf(), data))
    }

    pub fn from_bytes(path: PathBuf, data: Vec<u8>) -> Self {
        Self {
            path,
            data: Arc::new(data),
            sha256: OnceLock::new(),
            measurements: None,
            event_log_sha256: None,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn data(&self) -> &[u8] {
        &self.data
    }
    /// Cheap ownership for existing detector implementations; no image copy.
    pub fn shared_bytes(&self) -> Arc<Vec<u8>> {
        Arc::clone(&self.data)
    }
    /// Attach a separately captured log from the same boot. It is parsed once;
    /// callers remain responsible for acquisition provenance and TPM binding.
    pub fn with_event_log(mut self, log: &[u8]) -> Result<Self, DetectorError> {
        self.measurements = Some(crate::tcg::variable_measurements(log)?);
        self.event_log_sha256 = Some(format!("{:x}", Sha256::digest(log)));
        Ok(self)
    }
    pub fn variable_measurements(&self) -> Option<&[crate::tcg::VariableMeasurement]> {
        self.measurements.as_deref()
    }
    pub fn event_log_sha256(&self) -> Option<&str> {
        self.event_log_sha256.as_deref()
    }
    pub fn sha256(&self) -> &str {
        self.sha256
            .get_or_init(|| format!("{:x}", Sha256::digest(self.data())))
    }
}
