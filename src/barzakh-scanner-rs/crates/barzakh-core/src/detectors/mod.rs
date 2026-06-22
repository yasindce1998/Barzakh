pub mod acpi_integrity;
pub mod amt;
pub mod attestation;
pub mod differ;
pub mod entropy;
pub mod eventlog;
pub mod firmware_volume;
pub mod ftpm;
pub mod heci;
pub mod hook;
pub mod introspection;
pub mod mbr;
pub mod me_dma;
pub mod me_spi;
pub mod memory;
pub mod nvram_entropy;
pub mod optionrom;
pub mod pcr;
pub mod pcr_oracle;
pub mod pcr_replay;
pub mod runtime;
pub mod s3_bootscript;
pub mod secureboot;
pub mod secureboot_chain;
pub mod self_erasure;
pub mod smm;
pub mod smm_timing;
pub mod spi_integrity;
pub mod spi_region;
pub mod symexec;
pub mod timetravel;

use crate::baseline::Baseline;
use crate::detector::Detector;

pub fn create_all_detectors(baseline: Option<Baseline>) -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(pcr::PcrDetector::new(baseline.clone())),
        Box::new(memory::MemoryDetector::new(baseline.clone())),
        Box::new(hook::HookDetector::new(baseline.clone())),
        Box::new(eventlog::EventLogDetector::new()),
        Box::new(entropy::EntropyAnalyzer::new()),
        Box::new(secureboot::SecureBootDetector::new(baseline.clone())),
        Box::new(runtime::RuntimeHookDetector::new(baseline.clone())),
        Box::new(smm::SmmDetector::new()),
        Box::new(firmware_volume::FirmwareVolumeDetector::new()),
        Box::new(spi_integrity::SpiIntegrityDetector::new(baseline.clone())),
        Box::new(self_erasure::SelfErasureDetector::new()),
        Box::new(mbr::MbrDetector::new()),
        Box::new(pcr_oracle::PcrOracleDetector::new(baseline.clone())),
        Box::new(differ::FirmwareDifferDetector::new(baseline.clone())),
        Box::new(attestation::AttestationDetector::new()),
        Box::new(introspection::LiveDetector::new()),
        Box::new(timetravel::TimeTravelDetector::new()),
        Box::new(symexec::SymExecDetector::new()),
        Box::new(heci::HeciDetector::new()),
        Box::new(me_spi::MeSpiDetector::new()),
        Box::new(amt::AmtDetector::new()),
        Box::new(ftpm::FtpmDetector::new()),
        Box::new(me_dma::MeDmaDetector::new()),
        Box::new(spi_region::SpiRegionDetector::new()),
        Box::new(smm_timing::SmmTimingDetector::new()),
        Box::new(nvram_entropy::NvramEntropyDetector::new()),
        Box::new(s3_bootscript::S3BootscriptDetector::new()),
        Box::new(secureboot_chain::SecurebootChainDetector::new()),
        Box::new(optionrom::OptionromDetector::new()),
        Box::new(acpi_integrity::AcpiIntegrityDetector::new()),
    ]
}
