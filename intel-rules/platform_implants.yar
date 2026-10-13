// Platform-specific markers modeled by the Barzakh adversary toolkit —
// automotive, IoT, and baseband implant families.

rule Automotive_CAN_Backdoor
{
  meta:
    family = "custom"
    description = "ECU backdoor emitting CAN injection frames"
  strings:
    $ecu = "ECU_BACKDOOR" ascii
    $can = { CAN_INJECT }
  condition:
    $ecu
}

rule Zephyr_Rtos_Implant
{
  meta:
    family = "custom"
    description = "Zephyr RTOS boot tamper implant"
  strings:
    $zephyr = "ZEPHYR_BOOT_TAMPER" ascii
    $shell = "zephyr.shell" ascii
  condition:
    $zephyr or $shell
}

rule RiscV_DMI_Unlock
{
  meta:
    family = "custom"
    description = "RISC-V debug module interface unlock sequence"
  strings:
    $dmi = { 2D 44 4D 49 2D }
    $dmcontrol = { 04 00 00 00 }
  condition:
    $dmi and $dmcontrol
}

rule Android_VBMeta_Tamper
{
  meta:
    family = "custom"
    description = "Android verified boot (vbmeta/AVB) tampering"
  strings:
    $vbmeta = "vbmeta" ascii
    $rollback = "AVB ROLLBACK" ascii
  condition:
    $vbmeta and $rollback
}
