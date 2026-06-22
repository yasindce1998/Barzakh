/** @file
  ME SPI Manipulation Emulation - Header

  Models direct manipulation of the Intel Management Engine (ME) region
  within the SPI flash descriptor. This module emulates locating the SPI
  controller via PCH RCBA, reading the flash descriptor, parsing region
  boundaries, and modifying the ME region partition table.

  All operations are SIMULATED - no actual SPI hardware is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ME_SPI_MANIPULATION_H_
#define ME_SPI_MANIPULATION_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define SIMULATION_MODE  TRUE

#define MESPI_DEBUG_PREFIX  "[ME-SPI-Emu] "

//
// SPI controller defines
//
#define SPI_FLASH_DESCRIPTOR_SIG   0x0FF0A55A
#define SPIBAR_OFFSET              0x3800
#define PCH_RCBA_BASE              0xFED1C000
#define FLMAP0_OFFSET              0x14
#define FLMAP1_OFFSET              0x18
#define FLREG0_BIOS_OFFSET         0x54
#define FLREG1_ME_OFFSET           0x58
#define FLREG2_GBE_OFFSET          0x5C
#define FLOCKDN_BIT                BIT15
#define ME_REGION_SIZE             0x180000

//
// Flash region descriptor
//
typedef struct {
  UINT32    Base;
  UINT32    Limit;
  UINT32    Size;
} FLASH_REGION_DESCRIPTOR;

//
// ME SPI manipulation state machine
//
typedef enum {
  MeSpiStateInit = 0,
  MeSpiStateLocated,
  MeSpiStateDescriptorRead,
  MeSpiStateModified,
  MeSpiStateComplete,
  MeSpiStateError
} ME_SPI_STATE;

//
// ME region modification tracking
//
typedef struct {
  UINT32    OrigBase;
  UINT32    OrigLimit;
  UINT32    ModifiedBase;
  UINT32    ModifiedLimit;
} ME_REGION_INFO;

//
// Module context structure
//
typedef struct {
  BOOLEAN                Initialized;
  ME_SPI_STATE           State;

  // SPI controller location
  UINT64                 SpiBarBase;

  // Flash descriptor buffer (4KB)
  UINT8                  FlashDescriptor[4096];

  // ME region tracking
  ME_REGION_INFO         MeRegion;

  // FLOCKDN status
  BOOLEAN                FlockdnStatus;

  // Write operation tracking
  UINT32                 WriteAttempts;
  UINT32                 SuccessfulWrites;
} ME_SPI_CONTEXT;

EFI_STATUS
EFIAPI
InitializeMeSpiManipulation (
  OUT ME_SPI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateSpiController (
  IN OUT ME_SPI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ReadFlashDescriptor (
  IN OUT ME_SPI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ModifyMeRegion (
  IN OUT ME_SPI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
PersistMeSpiModification (
  IN OUT ME_SPI_CONTEXT  *Context
  );

VOID
EFIAPI
LogMeSpiStatus (
  IN ME_SPI_CONTEXT  *Context
  );

#endif // ME_SPI_MANIPULATION_H_
