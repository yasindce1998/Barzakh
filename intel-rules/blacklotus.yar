// BlackLotus (CVE-2023-24932) — Secure Boot bypass via MOK abuse and
// boot services hooking. Matches the marker set modeled by the platform.

rule BlackLotus_MOK_Abuse
{
  meta:
    family = "BlackLotus"
    cve = "CVE-2023-24932"
    description = "MOK list abuse for Secure Boot bypass"
  strings:
    $moklist_utf16 = { 4D 00 6F 00 6B 00 4C 00 69 00 73 00 74 00 }
    $shim_path = "\\EFI\\Microsoft\\Boot\\shimx64.efi" ascii
    $marker = "BlackLotus" ascii
  condition:
    $moklist_utf16 or $shim_path or $marker
}

rule BlackLotus_Bcd_Tamper
{
  meta:
    family = "BlackLotus"
    cve = "CVE-2023-24932"
    description = "BCD store tampering stage"
  strings:
    $bcd = "BcdStore" ascii
    $bootmgr = { 62 6F 6F 74 6D 67 72 }
  condition:
    $bcd and $bootmgr
}

rule Bootkit_Hook_Prologue
{
  meta:
    family = "generic"
    description = "jmp [rip+disp32] hook prologue followed by a bootkit marker"
  strings:
    $hook = { FF 25 ?? ?? ?? ?? }
    $marker = { 48 B8 55 45 46 49 5F 42 4B 21 }
    $loop = { EB FE }
  condition:
    $hook and $marker and not $loop
}
