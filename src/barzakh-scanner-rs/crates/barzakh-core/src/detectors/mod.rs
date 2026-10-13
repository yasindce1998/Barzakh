pub mod acpi_integrity;
pub mod amd_psp;
pub mod amt;
pub mod android_avb;
pub mod android_binary_transparency;
pub mod android_bootconfig;
pub mod android_bootctrl;
pub mod android_chain_validator;
pub mod android_dice;
pub mod android_fastboot;
pub mod android_gki_boot;
pub mod android_init_verity;
pub mod android_keymint;
pub mod android_pkvm;
pub mod android_rkp;
pub mod android_trusty;
pub mod android_vbmeta_chain;
pub mod android_vendor_dlkm;
pub mod apple_img4;
pub mod arm_tbbr;
pub mod arm_trustzone;
pub mod asus_nvram;
pub mod attestation;
pub mod auth_variable;
pub mod automotive_ecu;
pub mod baseband_firmware;
pub mod baseband_rtos;
pub mod blacklotus;
pub mod bluetooth_firmware;
pub mod bmc_spi;
pub mod boot_guard;
pub mod boot_guard_km;
pub mod can_injection;
pub mod capsule_update;
pub mod ccsds_telecommand;
pub mod confidential_vm;
pub mod csme_update;
pub mod cxl_device;
pub mod debug_interface;
pub mod dell_bios_connect;
pub mod differ;
pub mod dxe_dispatcher;
pub mod entropy;
pub mod esp_integrity;
pub mod eventlog;
pub mod firmware_volume;
pub mod five_g_ran_firmware;
pub mod ftpm;
pub mod gnss_receiver;
pub mod heci;
pub mod hook;
pub mod hpc_monitor;
pub mod http_boot;
pub mod ibm_opal;
pub mod idrac_spi;
pub mod ims_firmware;
pub mod inmarsat_terminal;
pub mod insyde_smm;
pub mod introspection;
pub mod iommu_dmar;
pub mod ios_amfi;
pub mod ios_ane_boot;
pub mod ios_iboot;
pub mod ios_ktrr;
pub mod ios_local_policy;
pub mod ios_ppl;
pub mod ios_secure_enclave;
pub mod ios_sep_downgrade;
pub mod ios_trustcache;
pub mod iot_rtos;
pub mod iot_zephyr;
pub mod linux_bootchain;
pub mod logofail;
pub mod lvfs_integrity;
pub mod mbr;
pub mod me_dma;
pub mod me_manufacturing_mode;
pub mod me_spi;
pub mod me_version_chain;
pub mod memory;
pub mod microcode_injection;
pub mod msi_key_reuse;
pub mod network_boot;
pub mod nlp_strings;
pub mod nsp_command;
pub mod nvidia_tegra;
pub mod nvram_entropy;
pub mod open_ran;
pub mod opensbi;
pub mod optionrom;
pub mod pcr;
pub mod pcr_oracle;
pub mod pcr_replay;
pub mod pei_implant;
pub mod pixiefail;
pub mod pluton;
pub mod pmp_bypass;
pub mod psp_secure_debug;
pub mod psp_trustlets;
pub mod psp_version_chain;
pub mod reloader;
pub mod riscv_bootrom;
pub mod riscv_debug;
pub mod rowhammer;
pub mod runtime;
pub mod s3_bootscript;
pub mod satellite_bus;
pub mod satellite_ground_station;
pub mod satellite_modem;
pub mod satellite_transponder;
pub mod sbat;
pub mod secureboot;
pub mod secureboot_chain;
pub mod secureboot_dbx;
pub mod self_erasure;
pub mod sim_applet;
pub mod small_cell;
pub mod smm;
pub mod smm_timing;
pub mod smu_firmware;
pub mod spectre_gadgets;
pub mod spi_integrity;
pub mod spi_region;
pub mod starlink_terminal;
pub mod symexec;
pub mod thermal_covert;
pub mod timetravel;
pub mod tpm_command;
pub mod voltage_glitch;
pub mod volte_firmware;
pub mod wifi_dxe;
pub mod wifi_firmware;
pub mod windows_bootchain;

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
        Box::new(logofail::LogofailDetector::new()),
        Box::new(pixiefail::PixiefailDetector::new()),
        Box::new(blacklotus::BlacklotusDetector::new()),
        Box::new(amd_psp::AmdPspDetector::new()),
        Box::new(boot_guard::BootGuardDetector::new()),
        Box::new(auth_variable::AuthVariableDetector::new()),
        Box::new(dxe_dispatcher::DxeDispatcherDetector::new()),
        Box::new(pei_implant::PeiImplantDetector::new()),
        Box::new(capsule_update::CapsuleUpdateDetector::new()),
        Box::new(cxl_device::CxlDeviceDetector::new()),
        Box::new(arm_trustzone::ArmTrustzoneDetector::new()),
        Box::new(opensbi::OpensbiDetector::new()),
        Box::new(pmp_bypass::PmpBypassDetector::new()),
        Box::new(linux_bootchain::LinuxBootchainDetector::new()),
        Box::new(reloader::ReloaderDetector::new()),
        Box::new(sbat::SbatDetector::new()),
        Box::new(esp_integrity::EspIntegrityDetector::new()),
        Box::new(confidential_vm::ConfidentialVmDetector::new()),
        Box::new(bmc_spi::BmcSpiDetector::new()),
        Box::new(http_boot::HttpBootDetector::new()),
        Box::new(tpm_command::TpmCommandDetector::new()),
        Box::new(arm_tbbr::ArmTbbrDetector::new()),
        Box::new(wifi_dxe::WifiDxeDetector::new()),
        Box::new(pluton::PlutonDetector::new()),
        Box::new(microcode_injection::MicrocodeInjectionDetector::new()),
        Box::new(spectre_gadgets::SpectreGadgetsDetector::new()),
        Box::new(thermal_covert::ThermalCovertDetector::new()),
        Box::new(voltage_glitch::VoltageGlitchDetector::new()),
        Box::new(debug_interface::DebugInterfaceDetector::new()),
        Box::new(rowhammer::RowhammerDetector::new()),
        Box::new(dell_bios_connect::DellBiosConnectDetector::new()),
        Box::new(asus_nvram::AsusNvramDetector::new()),
        Box::new(msi_key_reuse::MsiKeyReuseDetector::new()),
        Box::new(insyde_smm::InsydeSmmDetector::new()),
        Box::new(idrac_spi::IdracSpiDetector::new()),
        Box::new(lvfs_integrity::LvfsIntegrityDetector::new()),
        Box::new(android_pkvm::AndroidPkvmDetector::new()),
        Box::new(android_dice::AndroidDiceDetector::new()),
        Box::new(android_gki_boot::AndroidGkiBootDetector::new()),
        Box::new(android_rkp::AndroidRkpDetector::new()),
        Box::new(android_binary_transparency::AndroidBinaryTransparencyDetector::new()),
        Box::new(android_trusty::AndroidTrustyDetector::new()),
        Box::new(android_bootctrl::AndroidBootctrlDetector::new()),
        Box::new(android_vendor_dlkm::AndroidVendorDlkmDetector::new()),
        Box::new(android_bootconfig::AndroidBootconfigDetector::new()),
        Box::new(iommu_dmar::IommuDmarDetector::new()),
        Box::new(secureboot_dbx::SecurebootDbxDetector::new()),
        Box::new(apple_img4::AppleImg4Detector::new()),
        Box::new(windows_bootchain::WindowsBootchainDetector::new()),
        Box::new(android_avb::AndroidAvbDetector::new()),
        Box::new(android_fastboot::AndroidFastbootDetector::new()),
        Box::new(android_keymint::AndroidKeymintDetector::new()),
        Box::new(wifi_firmware::WifiFirmwareDetector::new()),
        Box::new(network_boot::NetworkBootDetector::new()),
        Box::new(bluetooth_firmware::BluetoothFirmwareDetector::new()),
        Box::new(ios_trustcache::IosTrustcacheDetector::new()),
        Box::new(ios_amfi::IosAmfiDetector::new()),
        Box::new(ios_ktrr::IosKtrrDetector::new()),
        Box::new(ios_sep_downgrade::IosSepDowngradeDetector::new()),
        Box::new(me_manufacturing_mode::MeManufacturingModeDetector::new()),
        Box::new(me_version_chain::MeVersionChainDetector::new()),
        Box::new(boot_guard_km::BootGuardKmDetector::new()),
        Box::new(csme_update::CsmeUpdateDetector::new()),
        Box::new(psp_version_chain::PspVersionChainDetector::new()),
        Box::new(psp_trustlets::PspTrustletsDetector::new()),
        Box::new(smu_firmware::SmuFirmwareDetector::new()),
        Box::new(psp_secure_debug::PspSecureDebugDetector::new()),
        Box::new(android_vbmeta_chain::AndroidVbmetaChainDetector::new()),
        Box::new(android_init_verity::AndroidInitVerityDetector::new()),
        Box::new(android_chain_validator::AndroidChainValidatorDetector::new()),
        Box::new(ios_iboot::IosIbootDetector::new()),
        Box::new(ios_ppl::IosPplDetector::new()),
        Box::new(ios_secure_enclave::IosSecureEnclaveDetector::new()),
        Box::new(ios_local_policy::IosLocalPolicyDetector::new()),
        Box::new(ios_ane_boot::IosAneBootDetector::new()),
        Box::new(baseband_firmware::BasebandFirmwareDetector::new()),
        Box::new(five_g_ran_firmware::FiveGRanFirmwareDetector::new()),
        Box::new(sim_applet::SimAppletDetector::new()),
        Box::new(ims_firmware::ImsFirmwareDetector::new()),
        Box::new(baseband_rtos::BasebandRtosDetector::new()),
        Box::new(open_ran::OpenRanDetector::new()),
        Box::new(small_cell::SmallCellDetector::new()),
        Box::new(volte_firmware::VolteFirmwareDetector::new()),
        Box::new(satellite_modem::SatelliteModemDetector::new()),
        Box::new(gnss_receiver::GnssReceiverDetector::new()),
        Box::new(satellite_ground_station::SatelliteGroundStationDetector::new()),
        Box::new(starlink_terminal::StarlinkTerminalDetector::new()),
        Box::new(satellite_transponder::SatelliteTransponderDetector::new()),
        Box::new(inmarsat_terminal::InmarsatTerminalDetector::new()),
        Box::new(satellite_bus::SatelliteBusDetector::new()),
        Box::new(ccsds_telecommand::CcsdsTelecommandDetector::new()),
        Box::new(nvidia_tegra::NvidiaTegraDetector::new()),
        Box::new(nsp_command::NspCommandDetector::new()),
        Box::new(ibm_opal::IbmOpalDetector::new()),
        Box::new(riscv_bootrom::RiscVBootRomDetector::new()),
        Box::new(riscv_debug::RiscVDebugDetector::new()),
        Box::new(automotive_ecu::AutomotiveEcuDetector::new()),
        Box::new(can_injection::CanInjectionDetector::new()),
        Box::new(iot_zephyr::IotZephyrDetector::new()),
        Box::new(iot_rtos::IotRtosDetector::new()),
        Box::new(hpc_monitor::HpcMonitorDetector::new()),
        Box::new(nlp_strings::NlpStringsDetector::new()),
    ]
}
