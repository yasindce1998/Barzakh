//! Machine-learning analysis for the Barzakh firmware scanner.
//!
//! - [`features`]: structural feature extraction from firmware images.
//! - [`iforest`]: isolation-forest anomaly detection with an `ml_anomaly`
//!   detector usable directly by the scanner.
//! - [`classifier`]: logistic-regression malicious/benign classifier trained
//!   on corpus features (gradient descent, JSON-serializable model).
//! - [`nlp`]: NLP-grade string analysis (obfuscation indicators, suspicious
//!   keywords, string entropy).

pub mod classifier;
pub mod features;
pub mod iforest;
pub mod nlp;
pub mod train;
