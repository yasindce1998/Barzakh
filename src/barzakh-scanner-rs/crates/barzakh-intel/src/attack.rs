//! MITRE ATT&CK mapping for Barzakh detectors and findings.

use barzakh_core::Finding;
use serde::Serialize;

/// An ATT&CK technique reference.
#[derive(Debug, Clone, Serialize)]
pub struct Technique {
    pub id: &'static str,
    pub name: &'static str,
}

/// Mapping table: detector name → ATT&CK techniques.
///
/// Techniques follow MITRE ATT&CK Enterprise v14 terminology for firmware
/// and boot-chain attacks.
pub fn techniques_for_detector(detector: &str) -> Vec<Technique> {
    let ids: &[&'static str] = match detector {
        "blacklotus" | "secureboot" | "secureboot_chain" | "secureboot_dbx" | "sbat"
        | "auth_variable" | "reloader" => &["T1542.001", "T1553.002"],
        "logofail" | "pixiefail" | "http_boot" | "network_boot" => &["T1190", "T1542.001"],
        "hook" | "memory" | "runtime" | "live" => &["T1055", "T1547"],
        "smm" | "smm_timing" | "insyde_smm" | "s3_bootscript" => &["T1542.001", "T1068"],
        "firmware_volume" | "spi_integrity" | "spi_region" | "differ" | "esp_integrity"
        | "pei_implant" | "dxe_dispatcher" | "capsule_update" | "lvfs_integrity"
        | "csme_update" | "me_version_chain" => &["T1542.001", "T1485"],
        "heci" | "amt" | "me_dma" | "me_manufacturing_mode" | "idrac_spi" | "bmc_spi" => {
            &["T1542.001", "T1210"]
        }
        "ftpm" | "tpm_command" | "pcr" | "pcr_oracle" | "pcr_replay" | "attestation"
        | "eventlog" => &["T1552.004", "T1600"],
        "amd_psp" | "psp_secure_debug" | "psp_trustlets" | "psp_version_chain" | "smu_firmware"
        | "pluton" => &["T1542.001"],
        "boot_guard" | "boot_guard_km" | "msi_key_reuse" | "confidential_vm" => &["T1553.002"],
        "acpi_integrity" | "iommu_dmar" | "cxl_device" | "optionrom" => &["T1200", "T1547"],
        "linux_bootchain" | "windows_bootchain" | "mbr" => &["T1542.003", "T1542.001"],
        "arm_trustzone" | "arm_tbbr" | "opensbi" | "pmp_bypass" | "riscv_bootrom"
        | "riscv_debug" => &["T1542.001", "T1611"],
        "android_pkvm"
        | "android_dice"
        | "android_gki_boot"
        | "android_rkp"
        | "android_trusty"
        | "android_avb"
        | "android_vbmeta_chain"
        | "android_init_verity"
        | "android_fastboot"
        | "android_keymint"
        | "android_binary_transparency"
        | "android_chain_validator"
        | "android_bootctrl"
        | "android_vendor_dlkm"
        | "android_bootconfig" => &["T1542.001", "T1627"],
        "apple_img4" | "ios_iboot" | "ios_amfi" | "ios_ktrr" | "ios_ppl" | "ios_local_policy"
        | "ios_secure_enclave" | "ios_sep_downgrade" | "ios_trustcache" | "ios_ane_boot" => {
            &["T1542.001", "T1627"]
        }
        "baseband_firmware"
        | "baseband_rtos"
        | "five_g_ran_firmware"
        | "ims_firmware"
        | "open_ran"
        | "sim_applet"
        | "small_cell"
        | "volte_firmware" => &["T1542.001"],
        "ccsds_telecommand"
        | "gnss_receiver"
        | "satellite_bus"
        | "satellite_modem"
        | "starlink_terminal"
        | "satellite_transponder"
        | "inmarsat_terminal"
        | "satellite_ground_station" => &["T1542.001", "T1584"],
        "wifi_firmware" | "wifi_dxe" | "bluetooth_firmware" => &["T1542.001", "T1584"],
        "microcode_injection"
        | "spectre_gadgets"
        | "thermal_covert"
        | "voltage_glitch"
        | "debug_interface"
        | "rowhammer"
        | "hpc_monitor" => &["T1011", "T1542.001"],
        "nvidia_tegra" | "nsp_command" | "ibm_opal" => &["T1542.001", "T1200"],
        "automotive_ecu" | "can_injection" => &["T1542.001", "T1584"],
        "iot_zephyr" | "iot_rtos" => &["T1542.001"],
        "entropy" | "self_erasure" | "timetravel" | "symexec" | "nvram_entropy" => &["T1070.004"],
        "nlp_strings" | "ioc_feed" | "yara_rules" => &["T1583.001"],
        "dell_bios_connect" | "asus_nvram" => &["T1190", "T1542.001"],
        _ => &["T1542.001"],
    };

    ids.iter()
        .map(|&id| Technique {
            id,
            name: name_for(id),
        })
        .collect()
}

/// Human-readable names for the referenced techniques.
pub fn name_for(technique_id: &str) -> &'static str {
    match technique_id {
        "T1011" => "Exfiltration Over Other Network Medium",
        "T1055" => "Process Injection",
        "T1068" => "Exploitation for Privilege Escalation",
        "T1070.004" => "Indicator Removal: File Deletion",
        "T1190" => "Exploit Public-Facing Application",
        "T1200" => "Hardware Additions",
        "T1210" => "Exploitation of Remote Services",
        "T1485" => "Data Destruction",
        "T1542.001" => "Create or Modify System Process: System Firmware",
        "T1542.003" => "Create or Modify System Process: Bootkit",
        "T1547" => "Boot or Logon Autostart Execution",
        "T1552.004" => "Unsecured Credentials: Private Keys",
        "T1553.002" => "Subvert Trust Controls: Code Signing",
        "T1583.001" => "Acquire Infrastructure: Domains",
        "T1584" => "Compromise Infrastructure",
        "T1600" => "Weaken Encryption",
        "T1611" => "Escape to Host",
        "T1627" => "Execution Guardrails",
        _ => "Unknown technique",
    }
}

/// Map a finding to its ATT&CK techniques.
pub fn techniques_for_finding(finding: &Finding) -> Vec<Technique> {
    techniques_for_detector(&finding.detector)
}

/// Render a kill-chain summary: unique techniques across all findings.
#[derive(Debug, Clone, Serialize)]
pub struct AttackMap {
    pub techniques: Vec<Technique>,
    /// Detector → technique IDs.
    pub by_detector: Vec<DetectorMapping>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DetectorMapping {
    pub detector: String,
    pub techniques: Vec<Technique>,
}

/// Build the ATT&CK mapping for a set of findings.
pub fn map_findings(findings: &[Finding]) -> AttackMap {
    let mut by_detector: Vec<DetectorMapping> = Vec::new();
    let mut seen: Vec<&str> = Vec::new();

    for finding in findings {
        if seen.contains(&finding.detector.as_str()) {
            continue;
        }
        seen.push(&finding.detector);
        by_detector.push(DetectorMapping {
            detector: finding.detector.clone(),
            techniques: techniques_for_finding(finding),
        });
    }

    let mut techniques: Vec<Technique> = Vec::new();
    for mapping in &by_detector {
        for t in &mapping.techniques {
            if !techniques.iter().any(|existing| existing.id == t.id) {
                techniques.push(t.clone());
            }
        }
    }

    AttackMap {
        techniques,
        by_detector,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use barzakh_core::Severity;

    #[test]
    fn secure_boot_detectors_map_to_firmware_persistence() {
        let techniques = techniques_for_detector("blacklotus");
        let ids: Vec<&str> = techniques.iter().map(|t| t.id).collect();
        assert!(ids.contains(&"T1542.001"));
        assert!(ids.contains(&"T1553.002"));
    }

    #[test]
    fn unknown_detector_gets_default() {
        let techniques = techniques_for_detector("nonexistent_detector");
        assert!(!techniques.is_empty());
    }

    #[test]
    fn map_findings_dedupes_techniques() {
        let findings = vec![
            Finding::new("blacklotus", Severity::Critical, "a", "d"),
            Finding::new("secureboot", Severity::High, "b", "d"),
        ];
        let map = map_findings(&findings);
        assert_eq!(map.by_detector.len(), 2);
        let ids: Vec<&str> = map.techniques.iter().map(|t| t.id).collect();
        assert_eq!(
            ids.len(),
            ids.iter().collect::<std::collections::HashSet<_>>().len()
        );
    }

    #[test]
    fn technique_names_resolve() {
        assert_eq!(
            name_for("T1542.003"),
            "Create or Modify System Process: Bootkit"
        );
    }
}
