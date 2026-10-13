// LoJax — first in-the-wild UEFI rootkit (APT28). SPI implant plus
// Windows-side driver components.

rule LoJax_SPI_Implant
{
  meta:
    family = "LoJax"
    description = "LoJax-style SPI implant marker bytes"
  strings:
    $marker = { DE AD BE EF }
    $name = "LoJax" ascii
  condition:
    all of them
}

rule LoJax_APUSER_Driver
{
  meta:
    family = "LoJax"
    description = "APUSER driver component with kernel access stubs"
  strings:
    $apuser = "APUSER" ascii
    $devmem = "/dev/mem" ascii
  condition:
    $apuser or $devmem
}
