// CosmicStrand / MoonBounce / MosaicRegressor — SPI-resident implants
// hooked into the boot flow. Uses jump patterns to match hook stubs that
// store a marker a few bytes after the hook prologue.

rule CosmicStrand_Hook
{
  meta:
    family = "CosmicStrand"
    description = "CosmicStrand boot flow hook"
  strings:
    $name = "CosmicStrand" ascii
    $hook_gap = { EB FE [8-64] 43 6F 73 }
  condition:
    $name or $hook_gap
}

rule MoonBounce_SPI_Implant
{
  meta:
    family = "MoonBounce"
    description = "MoonBounce SPI implant with delayed marker"
  strings:
    $name = "MoonBounce" ascii
    $marker = { 4D 6F 6F 6E [4-32] 42 6F 75 6E 63 65 }
  condition:
    any of them
}

rule MosaicRegressor_Volume_Overlay
{
  meta:
    family = "MosaicRegressor"
    description = "MosaicRegressor implant stored outside firmware volumes"
  strings:
    $name = "MosaicRegressor" ascii
    $fvh = { 5F 46 56 48 }
    $marker = { 48 B8 55 45 46 49 5F 42 4B 21 }
  condition:
    $name or ($fvh and $marker)
}
