//! Firmware knowledge base: crowdsourced, anonymizable firmware profiles.

use std::path::Path;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A firmware profile entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareProfile {
    pub sha256: String,
    pub size: u64,
    pub vendor: String,
    pub device: String,
    #[serde(default)]
    pub family: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// Related CVE identifiers.
    #[serde(default)]
    pub cves: Vec<String>,
    #[serde(default)]
    pub known_clean: bool,
    #[serde(default)]
    pub created: Option<String>,
}

impl FirmwareProfile {
    /// Build a profile from a firmware image.
    pub fn from_image(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let digest = hasher.finalize();
        Self {
            sha256: digest.iter().map(|b| format!("{b:02x}")).collect(),
            size: data.len() as u64,
            vendor: String::new(),
            device: String::new(),
            family: None,
            version: None,
            arch: None,
            notes: None,
            cves: Vec::new(),
            known_clean: false,
            created: Some(chrono::Utc::now().to_rfc3339()),
        }
    }

    /// Anonymized copy: vendor/device/notes replaced by hash prefixes so the
    /// profile can be shared without revealing the exact deployment.
    pub fn anonymized(&self) -> Self {
        let prefix = |input: &str| {
            let mut hasher = Sha256::new();
            hasher.update(input.as_bytes());
            let digest = hasher.finalize();
            format!(
                "anon-{}",
                digest
                    .iter()
                    .take(4)
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            )
        };
        Self {
            sha256: self.sha256.clone(),
            size: self.size,
            vendor: prefix(&self.vendor),
            device: prefix(&self.device),
            family: self.family.clone(),
            version: None,
            arch: self.arch.clone(),
            notes: None,
            cves: self.cves.clone(),
            known_clean: self.known_clean,
            created: self.created.clone(),
        }
    }
}

/// Import/export bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileBundle {
    pub format_version: u32,
    pub anonymized: bool,
    pub profiles: Vec<FirmwareProfile>,
}

/// SQLite-backed knowledge base.
pub struct KnowledgeBase {
    conn: Connection,
}

impl KnowledgeBase {
    /// Open (creating if needed) the knowledge base at `path`.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let conn = if path == Path::new(":memory:") {
            Connection::open_in_memory()?
        } else {
            Connection::open(path)?
        };
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS profiles (
                sha256 TEXT PRIMARY KEY,
                size INTEGER NOT NULL,
                vendor TEXT NOT NULL,
                device TEXT NOT NULL,
                family TEXT,
                version TEXT,
                arch TEXT,
                notes TEXT,
                cves_json TEXT NOT NULL,
                known_clean INTEGER NOT NULL,
                created TEXT
            );",
        )?;
        Ok(Self { conn })
    }

    /// Insert or update a profile.
    pub fn upsert(&self, profile: &FirmwareProfile) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO profiles (sha256, size, vendor, device, family, version, arch, notes, \
             cves_json, known_clean, created) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
             ON CONFLICT(sha256) DO UPDATE SET vendor=?3, device=?4, family=?5, version=?6, \
             arch=?7, notes=?8, cves_json=?9, known_clean=?10",
            rusqlite::params![
                profile.sha256,
                profile.size,
                profile.vendor,
                profile.device,
                profile.family,
                profile.version,
                profile.arch,
                profile.notes,
                serde_json::to_string(&profile.cves)?,
                profile.known_clean as i64,
                profile.created,
            ],
        )?;
        Ok(())
    }

    fn row_to_profile(row: &rusqlite::Row<'_>) -> rusqlite::Result<FirmwareProfile> {
        let cves_json: String = row.get(8)?;
        Ok(FirmwareProfile {
            sha256: row.get(0)?,
            size: row.get::<_, i64>(1)? as u64,
            vendor: row.get(2)?,
            device: row.get(3)?,
            family: row.get(4)?,
            version: row.get(5)?,
            arch: row.get(6)?,
            notes: row.get(7)?,
            cves: serde_json::from_str(&cves_json).unwrap_or_default(),
            known_clean: row.get::<_, i64>(9)? != 0,
            created: row.get(10)?,
        })
    }

    /// List all profiles.
    pub fn list(&self) -> anyhow::Result<Vec<FirmwareProfile>> {
        let mut stmt = self.conn.prepare(
            "SELECT sha256, size, vendor, device, family, version, arch, notes, \
                          cves_json, known_clean, created FROM profiles ORDER BY created DESC",
        )?;
        let rows = stmt.query_map([], Self::row_to_profile)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Look up a profile by image hash.
    pub fn find_by_hash(&self, sha256: &str) -> anyhow::Result<Option<FirmwareProfile>> {
        let mut stmt = self.conn.prepare(
            "SELECT sha256, size, vendor, device, family, version, arch, notes, cves_json, \
             known_clean, created FROM profiles WHERE sha256 = ?1",
        )?;
        let mut rows = stmt.query_map([sha256], Self::row_to_profile)?;
        Ok(rows.next().transpose()?)
    }

    /// Full-text-ish search across vendor/device/family/notes.
    pub fn search(&self, query: &str) -> anyhow::Result<Vec<FirmwareProfile>> {
        let pattern = format!("%{}%", query.to_lowercase());
        let mut stmt = self.conn.prepare(
            "SELECT sha256, size, vendor, device, family, version, arch, notes, cves_json, \
             known_clean, created FROM profiles WHERE \
             lower(vendor) LIKE ?1 OR lower(device) LIKE ?1 OR lower(COALESCE(family,'')) LIKE ?1 \
             OR lower(COALESCE(notes,'')) LIKE ?1 ORDER BY created DESC",
        )?;
        let rows = stmt.query_map([&pattern], Self::row_to_profile)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Export profiles as a JSON bundle.
    pub fn export(&self, path: &Path, anonymize: bool) -> anyhow::Result<()> {
        let profiles = self.list()?;
        let profiles: Vec<FirmwareProfile> = if anonymize {
            profiles.iter().map(FirmwareProfile::anonymized).collect()
        } else {
            profiles
        };
        let bundle = ProfileBundle {
            format_version: 1,
            anonymized: anonymize,
            profiles,
        };
        std::fs::write(path, serde_json::to_string_pretty(&bundle)?)?;
        Ok(())
    }

    /// Import a profile bundle.
    pub fn import(&self, path: &Path) -> anyhow::Result<usize> {
        let bundle: ProfileBundle = serde_json::from_str(&std::fs::read_to_string(path)?)?;
        for profile in &bundle.profiles {
            self.upsert(profile)?;
        }
        Ok(bundle.profiles.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> FirmwareProfile {
        FirmwareProfile {
            sha256: "a".repeat(64),
            size: 1024,
            vendor: "ASUS".to_string(),
            device: "PRIME Z690-A".to_string(),
            family: Some("Intel 600-series".to_string()),
            version: Some("1.2.3".to_string()),
            arch: Some("x86_64".to_string()),
            notes: Some("Reference golden image".to_string()),
            cves: vec!["CVE-2024-5345".to_string()],
            known_clean: true,
            created: Some("2026-10-13T00:00:00+00:00".to_string()),
        }
    }

    #[test]
    fn upsert_list_find() {
        let kb = KnowledgeBase::open(Path::new(":memory:")).unwrap();
        kb.upsert(&sample_profile()).unwrap();
        let all = kb.list().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].vendor, "ASUS");

        let found = kb.find_by_hash(&"a".repeat(64)).unwrap().unwrap();
        assert_eq!(found.device, "PRIME Z690-A");
        assert_eq!(found.cves, vec!["CVE-2024-5345"]);
    }

    #[test]
    fn upsert_updates_existing() {
        let kb = KnowledgeBase::open(Path::new(":memory:")).unwrap();
        kb.upsert(&sample_profile()).unwrap();
        let mut updated = sample_profile();
        updated.vendor = "Gigabyte".to_string();
        kb.upsert(&updated).unwrap();
        assert_eq!(kb.list().unwrap().len(), 1);
        assert_eq!(
            kb.find_by_hash(&"a".repeat(64)).unwrap().unwrap().vendor,
            "Gigabyte"
        );
    }

    #[test]
    fn search_matches_fields() {
        let kb = KnowledgeBase::open(Path::new(":memory:")).unwrap();
        kb.upsert(&sample_profile()).unwrap();
        assert_eq!(kb.search("asus").unwrap().len(), 1);
        assert_eq!(kb.search("z690").unwrap().len(), 1);
        assert_eq!(kb.search("golden").unwrap().len(), 1);
        assert_eq!(kb.search("nonexistent").unwrap().len(), 0);
    }

    #[test]
    fn export_import_round_trip() {
        let dir = tempfile::dir();
        let kb = KnowledgeBase::open(Path::new(":memory:")).unwrap();
        kb.upsert(&sample_profile()).unwrap();

        let export_path = dir.path.join("profiles.json");
        kb.export(&export_path, false).unwrap();

        let kb2 = KnowledgeBase::open(Path::new(":memory:")).unwrap();
        assert_eq!(kb2.import(&export_path).unwrap(), 1);
        assert_eq!(kb2.list().unwrap().len(), 1);
    }

    #[test]
    fn anonymized_export_strips_identity() {
        let dir = tempfile::dir();
        let kb = KnowledgeBase::open(Path::new(":memory:")).unwrap();
        kb.upsert(&sample_profile()).unwrap();

        let export_path = dir.path.join("anon.json");
        kb.export(&export_path, true).unwrap();
        let bundle: ProfileBundle =
            serde_json::from_str(&std::fs::read_to_string(&export_path).unwrap()).unwrap();
        assert!(bundle.anonymized);
        assert_eq!(bundle.profiles.len(), 1);
        assert!(bundle.profiles[0].vendor.starts_with("anon-"));
        assert_eq!(bundle.profiles[0].device.len(), "anon-12345678".len());
        assert!(bundle.profiles[0].notes.is_none());
        assert_eq!(bundle.profiles[0].cves, vec!["CVE-2024-5345"]);
    }

    #[test]
    fn profile_from_image_hashes() {
        let profile = FirmwareProfile::from_image(&[0xAB; 512]);
        assert_eq!(profile.size, 512);
        assert_eq!(profile.sha256.len(), 64);
    }
}

/// Test-only tempdir helper (avoids a dev-dependency for other consumers).
#[cfg(test)]
mod tempfile {
    pub struct TempDir {
        pub path: std::path::PathBuf,
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    pub fn dir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "barzakh-kb-test-{}-{}",
            std::process::id(),
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }
}
