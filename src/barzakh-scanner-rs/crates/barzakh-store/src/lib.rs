//! Persistent storage for the Barzakh platform.
//!
//! - [`history`]: SQLite-backed scan history — record, list, diff and trend
//!   scan results over time.
//! - [`kb`]: the firmware knowledge base — crowdsourced, anonymizable
//!   profiles of analyzed firmware images.

pub mod history;
pub mod kb;
