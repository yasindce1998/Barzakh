pub mod acpi_backdoor;
pub mod amt_sol;
pub mod boot_services_hook;
pub mod ftpm_forge;
pub mod fv_tamper;
pub mod heci_traffic;
pub mod me_dma_inject;
pub mod me_spi_region;
pub mod nvram_capsule;
pub mod optionrom_inject;
pub mod pe_inject;
pub mod s3_bootscript_inject;
pub mod secureboot_bypass;
pub mod signature_plant;
pub mod smm_timing_anomaly;
pub mod spi_region_tamper;
pub mod trampoline;

use crate::Payload;

pub fn create_all_payloads() -> Vec<Box<dyn Payload>> {
    vec![
        Box::new(trampoline::TrampolinePayload),
        Box::new(boot_services_hook::BootServicesHookPayload),
        Box::new(pe_inject::PeInjectPayload),
        Box::new(fv_tamper::FirmwareVolumeTamperPayload),
        Box::new(signature_plant::SignaturePlantPayload),
        Box::new(heci_traffic::HeciTrafficPayload),
        Box::new(me_spi_region::MeSpiRegionPayload),
        Box::new(amt_sol::AmtSolPayload),
        Box::new(ftpm_forge::FtpmForgePayload),
        Box::new(me_dma_inject::MeDmaInjectPayload),
        Box::new(spi_region_tamper::SpiRegionTamperPayload),
        Box::new(smm_timing_anomaly::SmmTimingAnomalyPayload),
        Box::new(nvram_capsule::NvramCapsulePayload),
        Box::new(s3_bootscript_inject::S3BootscriptInjectPayload),
        Box::new(secureboot_bypass::SecurebootBypassPayload),
        Box::new(optionrom_inject::OptionromInjectPayload),
        Box::new(acpi_backdoor::AcpiBackdoorPayload),
    ]
}
