//! Threat intelligence for the Barzakh firmware scanner.
//!
//! - [`ioc`]: IOC feed ingestion and matching (hashes, byte patterns,
//!   variable names) exposed as a detector.
//! - [`yara`]: a YARA-subset rule engine (text + hex strings, `any of them`
//!   conditions) exposed as a detector.
//! - [`attack`]: MITRE ATT&CK mapping for detectors and findings.
//! - [`cve`]: CVE knowledge for detector families.
//! - [`misp`]: MISP event export of scan results.

pub mod attack;
pub mod cve;
pub mod ioc;
pub mod misp;
pub mod yara;
