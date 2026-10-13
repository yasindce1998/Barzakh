//! CVE knowledge base: map detectors and malware families to known
//! vulnerabilities and advisories.

use serde::Serialize;

/// A known vulnerability reference.
#[derive(Debug, Clone, Serialize)]
pub struct Vulnerability {
    pub cve: &'static str,
    pub description: &'static str,
    pub year: u16,
}

/// CVEs associated with a detector or family.
pub fn cves_for_detector(detector: &str) -> Vec<Vulnerability> {
    let entries: &[(&'static str, &'static str, u16)] = match detector {
        "blacklotus" | "secureboot_dbx" => &[(
            "CVE-2023-24932",
            "Windows Secure Boot security feature bypass via crafted boot manager (BlackLotus)",
            2023,
        )],
        "logofail" => &[(
            "CVE-2023-40238",
            "EDK II image parsing buffer overflow in BMP handling (LogoFAIL)",
            2023,
        )],
        "pixiefail" => &[
            (
                "CVE-2023-45229",
                "EDK II DHCPv6 option overflow in network boot (PixieFail)",
                2023,
            ),
            (
                "CVE-2023-45230",
                "EDK II DHCPv6 client DUID overflow (PixieFail)",
                2023,
            ),
        ],
        "tpm_command" => &[
            (
                "CVE-2023-1017",
                "TPM 2.0 reference implementation buffer overflow (out-of-bounds write)",
                2023,
            ),
            (
                "CVE-2023-1018",
                "TPM 2.0 reference implementation out-of-bounds read",
                2023,
            ),
        ],
        "reloader" => &[(
            "CVE-2024-7344",
            "Signed UEFI reloader loads untrusted PE payloads (How UEFI bootloaders are undermining Secure Boot)",
            2024,
        )],
        "insyde_smm" => &[(
            "CVE-2022-24894",
            "Insyde H2O IHISI SMM privilege escalation",
            2022,
        )],
        "asus_nvram" => &[(
            "CVE-2024-5345",
            "ASUS UEFI firmware update bypass via NVRAM variable manipulation",
            2024,
        )],
        "lvfs_integrity" => &[(
            "CVE-2020-28887",
            "fwupd / LVFS metadata signature verification weakness",
            2020,
        )],
        "linux_bootchain" => &[(
            "CVE-2024-1086",
            "Bootkitty-class GRUB signature verification bypass lineage",
            2024,
        )],
        _ => &[],
    };

    entries
        .iter()
        .map(|&(cve, description, year)| Vulnerability {
            cve,
            description,
            year,
        })
        .collect()
}

/// Known adversary families modeled by the platform, for reporting context.
pub const ADVERSARY_FAMILIES: &[(&str, &str)] = &[
    ("BlackLotus", "UEFI bootkit abusing Secure Boot bypass"),
    ("CosmicStrand", "SPI flash DXE persistence"),
    ("LoJax", "First in-the-wild UEFI implant"),
    ("MoonBounce", "Modified core DXE in SPI flash"),
    ("MosaicRegressor", "Multi-stage UEFI persistence framework"),
    ("FinSpy", "UEFI bootloader modification"),
    ("Hacking Team RCS", "UEFI rootkit with Option ROM"),
    ("Bootkitty", "First Linux UEFI bootkit"),
    ("LogoFAIL", "Image parser overflow in UEFI firmware"),
    ("PixieFail", "EDK II network stack overflows"),
];

/// Enrich a finding with CVE context when available.
pub fn enrich_description(detector: &str) -> Option<String> {
    let cves = cves_for_detector(detector);
    if cves.is_empty() {
        return None;
    }
    Some(
        cves.iter()
            .map(|c| format!("{} — {}", c.cve, c.description))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blacklotus_maps_to_cve_2023_24932() {
        let cves = cves_for_detector("blacklotus");
        assert_eq!(cves[0].cve, "CVE-2023-24932");
        assert!(cves[0].description.contains("BlackLotus"));
    }

    #[test]
    fn pixiefail_has_multiple_cves() {
        assert!(cves_for_detector("pixiefail").len() >= 2);
    }

    #[test]
    fn unknown_detector_has_no_cves() {
        assert!(cves_for_detector("nonsense").is_empty());
        assert!(enrich_description("nonsense").is_none());
    }
}
