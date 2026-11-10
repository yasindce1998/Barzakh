/*
 * Barzakh curated real-world firmware threat rule pack.
 *
 * These rules are modeled on public research (ESET Welivesecurity,
 * Cisco advisories, vendor PSIRTs) for real firmware implants and
 * bootkits: LoJax, BlackLotus, MoonBounce, ESPectre, Bootkitty. The
 * marker sets are Barzakh's reconstruction of the published TTPs and
 * are safe to redistribute.
 *
 * The pack is written in unmodified, standards-compliant YARA syntax
 * and exercises the engine's Phase 0.8 parity surface: regex strings,
 * text modifiers (wide/ascii/nocase/fullword), hex jumps, `filesize`,
 * the `pe` module subset, `of` set expressions with wildcards, string
 * operators and caller-provided external variables.
 *
 * Rules that reference external variables (marked in their meta)
 * require the scanner to pass `--define` values; without them the
 * rule stays quiet by design.
 */

import "pe"

rule UEFI_LoJax_SPI_Implant
{
    meta:
        family = "LoJax"
        cve = "CVE-2018-32198"
        description = "LoJax UEFI implant markers modeled on ESET research (Welivesecurity, 2018)"
        reference = "https://www.welivesecurity.com/2018/09/27/lojax-first-uefi-rootkit-found-malicious-update-process/"
    strings:
        $svc = "Windir_1"
        $driverpath = "\\SystemRoot\\System32\\drivers\\" ascii nocase
        $re_reg = /SYSTEM\\CurrentControlSet\\Services\\[A-Za-z]{4,12}/ nocase
        $hex_marker = { 4C 6F 4A 61 78 [10-40] 53 50 49 }
    condition:
        filesize < 400KB and
        2 of them and
        pe.is_pe and
        pe.machine == pe.MACHINE_I386 and
        pe.subsystem == pe.SUBSYSTEM_NATIVE
}

rule BlackLotus_Stage2_Bootkit
{
    meta:
        family = "BlackLotus"
        cve = "CVE-2022-21894"
        description = "BlackLotus UEFI bootkit stage-2 markers modeled on ESET research (2023)"
        reference = "https://www.welivesecurity.com/2023/03/01/blacklotus-uefi-bootkit-myth-confirmed/"
    strings:
        $mok = "MokManagerTUI" wide ascii
        $re_win = /Windows\\System32\\[a-z_]{3,20}\.sys/ nocase
        $hex = { 55 48 89 E5 [4-60] 48 8B 05 }
        $rk = "rk CheckFreeSpace" fullword
    condition:
        pe.is_pe and
        (pe.machine == pe.MACHINE_AMD64 or pe.machine == pe.MACHINE_I386) and
        pe.subsystem == pe.SUBSYSTEM_EFI_APPLICATION and
        (pe.characteristics & pe.DLL) == 0 and
        2 of ($mok, $re_win, $hex, $rk)
}

rule MoonBounce_SPI_Implant
{
    meta:
        family = "MoonBounce"
        description = "MoonBounce SPI implant driver markers modeled on ESET research (2022)"
        reference = "https://www.welivesecurity.com/2022/01/25/moonbounce-uefi-firmware-bootkit/"
    strings:
        $spi_reg = /SPI_BAR[0-9]?/ ascii
        $eeprom = "EepromWriteProtect" nocase fullword
        $hex = { 89 45 ?? 8B 4D [2-8] E8 }
    condition:
        pe.is_pe and
        pe.machine == pe.MACHINE_AMD64 and
        pe.number_of_sections >= 3 and
        pe.sections[0].name == ".text" and
        pe.entry_point > 0x1000 and
        2 of them
}

rule ESPectre_SPI_Modification
{
    meta:
        family = "ESPectre"
        description = "ESPectre-style SPI flash modification markers modeled on the Cisco 2018 advisory"
        reference = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181107-esp"
    strings:
        $magic = "SPIFLASH" wide ascii
        $re = /boot_sector_mod[a-z_]{0,16}/ nocase
    condition:
        filesize < 200KB and #re >= 2 and $magic
}

rule Bootkitty_EFI_Bootkit
{
    meta:
        family = "Bootkitty"
        description = "Bootkitty Linux UEFI bootkit markers modeled on ESET research (2024)"
        reference = "https://www.welivesecurity.com/en/eset-research/bootkitty-first-uefi-bootkit-mitigating-secure-boot/"
    strings:
        $banner = "Ubuntu Linux" wide
        $tag = "kitty" fullword nocase
        $re = /printk_init[A-Za-z_]{0,12}/ ascii
    condition:
        2 of them
}

rule Deployment_Revoked_Bootloader
{
    meta:
        description = "Deployment gate: flags bootloader builds on the local revocation list (external variable: revoked)"
        requires_externals = "revoked"
    strings:
        $build = "BUILD-REVOKED-7"
    condition:
        $build and revoked == true
}

rule Shim_Downgrade_Suspect
{
    meta:
        description = "Flags shim bootloader builds whose filename matches the downgrade-watch pattern (external variable: filename)"
        requires_externals = "filename"
    strings:
        $old = "SHIM-DOWNGRADE-MARK"
    condition:
        $old and filename matches /shimx64-[0-9]+\.efi/
}
