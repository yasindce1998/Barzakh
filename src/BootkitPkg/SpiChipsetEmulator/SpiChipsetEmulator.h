/** @file
  SPI Chipset Register Emulation - Header

  Models chipset register-level SPI flash manipulation techniques used by
  LoJax and similar bootkits. Focuses on BIOS_CNTL, HSFS/HSFC, PRx registers,
  and TOCTOU race conditions for bypassing write protections.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SPI_CHIPSET_EMULATOR_H_
#define SPI_CHIPSET_EMULATOR_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/IoLib.h>
#include <Library/PciLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define SPI_DEBUG_PREFIX  "[SpiChipset-Emu] "

//
// PCH LPC/eSPI Controller (B0:D31:F0)
//
#define LPC_PCI_BUS              0
#define LPC_PCI_DEV              31
#define LPC_PCI_FUNC             0

//
// BIOS_CNTL register (offset 0xDC on modern PCH)
//
#define BIOS_CNTL_OFFSET         0xDC
#define BIOS_CNTL_BIOSWE         BIT0   // BIOS Write Enable
#define BIOS_CNTL_BLE            BIT1   // BIOS Lock Enable
#define BIOS_CNTL_SMM_BWP       BIT5   // SMM BIOS Write Protect

//
// SPI Controller (B0:D31:F5)
//
#define SPI_PCI_BUS              0
#define SPI_PCI_DEV              31
#define SPI_PCI_FUNC             5

//
// SPIBAR (SPI Base Address Register) - from RCBA or PCI BAR0
//
#define SPIBAR_OFFSET            0x10

//
// Hardware Sequencing Flash Status (HSFS) - SPIBAR + 0x04
//
#define SPI_HSFS_OFFSET          0x04
#define SPI_HSFS_FDONE           BIT0   // Flash Cycle Done
#define SPI_HSFS_FCERR           BIT1   // Flash Cycle Error
#define SPI_HSFS_AEL             BIT2   // Access Error Log
#define SPI_HSFS_SCIP            BIT5   // SPI Cycle In Progress
#define SPI_HSFS_FDV             BIT14  // Flash Descriptor Valid
#define SPI_HSFS_FLOCKDN         BIT15  // Flash Configuration Lockdown

//
// Hardware Sequencing Flash Control (HSFC) - SPIBAR + 0x06
//
#define SPI_HSFC_OFFSET          0x06
#define SPI_HSFC_FGO             BIT0   // Flash Cycle Go
#define SPI_HSFC_FCYCLE_READ     0x00   // Read cycle
#define SPI_HSFC_FCYCLE_WRITE    0x02   // Write cycle
#define SPI_HSFC_FCYCLE_ERASE    0x03   // Block erase cycle
#define SPI_HSFC_FDBC_MASK       0x3F00 // Flash Data Byte Count

//
// Flash Protected Range registers (PRx) - SPIBAR + 0x84..0x90
//
#define SPI_PR0_OFFSET           0x84
#define SPI_PR_COUNT             5
#define SPI_PR_WPE               BIT31  // Write Protection Enable
#define SPI_PR_RPE               BIT15  // Read Protection Enable

//
// Flash Address (FADDR) - SPIBAR + 0x08
//
#define SPI_FADDR_OFFSET         0x08

//
// Flash Data registers - SPIBAR + 0x10..0x4F (64 bytes)
//
#define SPI_FDATA0_OFFSET        0x10
#define SPI_FDATA_COUNT          16

//
// SPI Opcode Menu registers
//
#define SPI_OPMENU_OFFSET        0x98
#define SPI_OPTYPE_OFFSET        0x96

//
// Flash regions
//
#define SPI_REGION_DESCRIPTOR    0
#define SPI_REGION_BIOS          1
#define SPI_REGION_ME            2
#define SPI_REGION_GBE           3
#define SPI_REGION_PLATFORM      4

#define MAX_PROTECTED_RANGES     5

typedef enum {
  SpiStateUninitialized = 0,
  SpiStateRegistersRead,
  SpiStateProtectionAnalyzed,
  SpiStateBypassAttempted,
  SpiStateWriteEnabled
} SPI_CHIPSET_STATE;

typedef struct {
  UINT32   BaseAddress;
  UINT32   LimitAddress;
  BOOLEAN  WriteProtected;
  BOOLEAN  ReadProtected;
} SPI_PROTECTED_RANGE;

typedef struct {
  BOOLEAN            Initialized;
  SPI_CHIPSET_STATE  State;

  // BIOS_CNTL register state
  UINT8              BiosCntl;
  BOOLEAN            BiosWeSet;
  BOOLEAN            BleSet;
  BOOLEAN            SmmBwpSet;

  // SPIBAR address
  UINT64             SpiBar;
  BOOLEAN            SpiBarValid;

  // HSFS/HSFC state
  UINT16             Hsfs;
  UINT16             Hsfc;
  BOOLEAN            FlockdnSet;
  BOOLEAN            FlashDescriptorValid;

  // Protected ranges
  SPI_PROTECTED_RANGE  ProtectedRanges[MAX_PROTECTED_RANGES];
  UINT32               ProtectedRangeCount;

  // TOCTOU attack state
  BOOLEAN            ToctouAttempted;
  BOOLEAN            ToctouSucceeded;
} SPI_CHIPSET_CONTEXT;

EFI_STATUS
EFIAPI
InitializeSpiChipset (
  OUT SPI_CHIPSET_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ReadChipsetRegisters (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
AnalyzeWriteProtection (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateBiosWeToggle (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateToctouBypass (
  IN OUT SPI_CHIPSET_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateHardwareSequencing (
  IN OUT SPI_CHIPSET_CONTEXT  *Context,
  IN     UINT8               CycleType,
  IN     UINT32              Address,
  IN     UINT32              DataSize
  );

VOID
EFIAPI
LogSpiChipsetStatus (
  IN     SPI_CHIPSET_CONTEXT  *Context
  );

#endif // SPI_CHIPSET_EMULATOR_H_
