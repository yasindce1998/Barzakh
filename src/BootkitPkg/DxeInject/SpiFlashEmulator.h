/** @file
  SPI Flash Emulator - Models LoJax-style Firmware Persistence

  Emulates SPI flash operations to model how bootkits achieve persistence
  by modifying firmware. This is a SIMULATION ONLY - no actual flash writes.

  LoJax Technique:
  1. Locate SPI flash controller
  2. Unlock flash regions
  3. Write modified DXE driver to Firmware Volume
  4. Update NVRAM variables to load implant
  5. Lock flash regions

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __SPI_FLASH_EMULATOR_H__
#define __SPI_FLASH_EMULATOR_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <BarzakhMode.h>

//
// SPI Flash Regions (Intel PCH)
//
#define SPI_REGION_DESCRIPTOR  0
#define SPI_REGION_BIOS        1
#define SPI_REGION_ME          2
#define SPI_REGION_GBE         3
#define SPI_REGION_PDR         4

//
// Flash Protection Bits
//
#define FLASH_PROTECTED_RANGE_ENABLE  BIT15
#define FLASH_WRITE_PROTECTED         BIT0
#define FLASH_READ_PROTECTED          BIT1

//
// PRx Register Count (Intel PCH supports up to 5 Protected Range registers)
//
#define SPI_PRX_MAX_COUNT  5

//
// SPI Protected Range Register (models Intel PCH PR0-PR4)
//
typedef struct {
  BOOLEAN   Enabled;
  UINT32    Base;           // Protected range base address (4KB aligned)
  UINT32    Limit;          // Protected range limit address (4KB aligned)
  BOOLEAN   WriteProtect;   // Write protection enabled
  BOOLEAN   ReadProtect;    // Read protection enabled
} SPI_PROTECTED_RANGE;

//
// Emulated flash size (16MB typical)
//
#define EMULATED_FLASH_SIZE  (16 * 1024 * 1024)

//
// SPI Flash Emulator Context
//
typedef struct {
  UINT32              Signature;
  BOOLEAN             Initialized;
  UINT8               *FlashMemory;          // Emulated flash contents
  UINT32              FlashSize;
  BOOLEAN             RegionLocked[5];       // Lock status for each region
  UINT32              WriteCount;            // Number of write operations
  UINT32              EraseCount;            // Number of erase operations
  BOOLEAN             PersistenceInstalled;  // Whether implant is installed
  //
  // 2024+ Platform Protection (Intel PCH PRx registers)
  //
  SPI_PROTECTED_RANGE ProtectedRanges[SPI_PRX_MAX_COUNT];
  BOOLEAN             FLOCKDN;              // Flash Lockdown — locks PRx config
  BOOLEAN             BiosWe;               // BIOS Write Enable
  BOOLEAN             BiosLe;               // BIOS Lock Enable (SMI on BiosWe change)
  BOOLEAN             SmiLock;              // SMI Lock (prevents SMI handler changes)
  UINT32              ProtectionBypassCount; // TOCTOU bypass attempts logged
} SPI_FLASH_EMULATOR;

#define SPI_FLASH_EMULATOR_SIGNATURE  SIGNATURE_32('S','P','I','E')

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
  );

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
  );

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
  );

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
  );

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
  );

/**
  Install persistent implant in emulated flash (LoJax technique).

  This simulates the LoJax bootkit's persistence mechanism:
  1. Unlock BIOS region
  2. Locate Firmware Volume
  3. Write modified DXE driver
  4. Update NVRAM to load implant
  5. Lock BIOS region

  @param[in]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS           Implant installed successfully.
  @retval EFI_INVALID_PARAMETER Emulator is NULL.
  @retval EFI_ALREADY_STARTED   Implant already installed.
**/
EFI_STATUS
EFIAPI
InstallPersistentImplant (
  IN SPI_FLASH_EMULATOR  *Emulator
  );

/**
  Configure a Protected Range register (PRx).

  Models Intel PCH PR0-PR4 registers. Once FLOCKDN is set,
  no further changes to protected ranges are allowed.

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
  );

/**
  Set Flash Lockdown (FLOCKDN) bit.

  Once set, PRx registers cannot be reconfigured until next reset.
  This models the hardware behavior where firmware sets PRx then locks.

  @param[in]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS  FLOCKDN set.
**/
EFI_STATUS
EFIAPI
SpiFlashSetFlockdn (
  IN SPI_FLASH_EMULATOR  *Emulator
  );

/**
  Check if an address is protected by PRx registers.

  @param[in]  Emulator      Pointer to emulator context.
  @param[in]  Address       Flash address to check.
  @param[in]  CheckWrite    TRUE to check write protection.

  @retval TRUE   Address is protected.
  @retval FALSE  Address is not protected.
**/
BOOLEAN
EFIAPI
IsAddressProtected (
  IN SPI_FLASH_EMULATOR  *Emulator,
  IN UINT32              Address,
  IN BOOLEAN             CheckWrite
  );

/**
  Emulate TOCTOU bypass of SPI write protections.

  Models the race condition exploited by LoJax/MosaicRegressor where
  the attacker clears BiosWe between the SMI handler check and the
  actual write operation. Simulation only.

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
  );

/**
  Log emulator statistics.

  @param[in]  Emulator  Pointer to emulator context.
**/
VOID
EFIAPI
LogEmulatorStatistics (
  IN SPI_FLASH_EMULATOR  *Emulator
  );

/**
  Cleanup emulator resources.

  @param[in]  Emulator  Pointer to emulator context.

  @retval EFI_SUCCESS  Cleanup successful.
**/
EFI_STATUS
EFIAPI
CleanupSpiFlashEmulator (
  IN SPI_FLASH_EMULATOR  *Emulator
  );

#endif // __SPI_FLASH_EMULATOR_H__

