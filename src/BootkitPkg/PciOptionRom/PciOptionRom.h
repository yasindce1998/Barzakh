/** @file
  PCI Option ROM Persistence Emulation - Header

  Models PCI expansion ROM persistence techniques. Enumerates PCI devices,
  reads Expansion ROM BARs, constructs option ROM headers with EFI-compatible
  format, and simulates ROM implant injection.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef PCI_OPTION_ROM_H_
#define PCI_OPTION_ROM_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/PciLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/Pci.h>
#include <BarzakhMode.h>

#define OPTROM_DEBUG_PREFIX  "[PciOptRom-Emu] "

//
// PCI Option ROM signatures
//
#define PCI_ROM_SIGNATURE            0xAA55
#define PCIR_SIGNATURE               0x52494350  // "PCIR"

//
// PCI config space offsets
//
#define PCI_VENDOR_ID_OFFSET         0x00
#define PCI_DEVICE_ID_OFFSET         0x02
#define PCI_CLASS_CODE_OFFSET        0x09
#define PCI_HEADER_TYPE_OFFSET       0x0E
#define PCI_EXPANSION_ROM_BAR        0x30
#define PCI_ROM_BAR_ENABLE           BIT0

//
// EFI PCI ROM image types
//
#define PCI_ROM_CODE_TYPE_PCAT       0x00
#define PCI_ROM_CODE_TYPE_OPEN_FW    0x01
#define PCI_ROM_CODE_TYPE_HP_PA      0x02
#define PCI_ROM_CODE_TYPE_EFI        0x03

//
// Maximum devices to scan
//
#define MAX_PCI_DEVICES              16
#define OPTROM_MAX_BUS               2     // Scan buses 0-1 (host bridge + PCIe root ports)
#define OPTROM_MAX_DEV               32
#define OPTROM_MAX_FUNC              8

//
// Simulated ROM sizes
//
#define OPTION_ROM_HEADER_SIZE       512
#define OPTION_ROM_PAYLOAD_SIZE      4096
#define OPTION_ROM_TOTAL_SIZE        (OPTION_ROM_HEADER_SIZE + OPTION_ROM_PAYLOAD_SIZE)

//
// PCIR data structure (PCI Data Structure per PCI Firmware Spec)
//
#pragma pack(1)

typedef struct {
  UINT16  Signature;       // 0xAA55
  UINT8   Reserved[0x16];  // Processor-specific
  UINT16  PcirOffset;      // Offset to PCI Data Structure
} PCI_ROM_HEADER;

typedef struct {
  UINT32  Signature;       // "PCIR"
  UINT16  VendorId;
  UINT16  DeviceId;
  UINT16  DeviceListOffset;
  UINT16  Length;          // PCIR structure length
  UINT8   Revision;
  UINT8   ClassCode[3];
  UINT16  ImageLength;    // In 512-byte units
  UINT16  CodeRevision;
  UINT8   CodeType;       // 0=x86, 3=EFI
  UINT8   Indicator;      // Bit 7: last image
  UINT16  MaxRuntimeSize; // In 512-byte units
  UINT16  ConfigUtilityOffset;
  UINT16  DmtfClpOffset;
} OPTROM_PCIR_DATA;

typedef struct {
  PCI_ROM_HEADER       RomHeader;
  OPTROM_PCIR_DATA     PcirData;
} OPTION_ROM_IMAGE;

#pragma pack()

typedef struct {
  UINT8   Bus;
  UINT8   Device;
  UINT8   Function;
  UINT16  VendorId;
  UINT16  DeviceId;
  UINT8   ClassCode[3];
  UINT32  ExpansionRomBar;
  BOOLEAN HasOptionRom;
  BOOLEAN RomEnabled;
} PCI_DEVICE_INFO;

typedef struct {
  BOOLEAN          Initialized;
  UINT32           State;

  // PCI enumeration
  PCI_DEVICE_INFO  Devices[MAX_PCI_DEVICES];
  UINT32           DeviceCount;
  UINT32           RomCapableCount;

  // Option ROM construction
  UINT8            *RomBuffer;
  UINT32           RomSize;
  BOOLEAN          RomConstructed;

  // Injection state
  UINT32           TargetDevice;
  BOOLEAN          InjectionAttempted;
  BOOLEAN          InjectionSucceeded;
} PCI_OPTROM_CONTEXT;

typedef enum {
  OptRomStateUninitialized = 0,
  OptRomStateDevicesScanned,
  OptRomStateRomConstructed,
  OptRomStateInjectionSimulated
} PCI_OPTROM_STATE;

EFI_STATUS
EFIAPI
InitializePciOptRom (
  OUT PCI_OPTROM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ScanPciDevices (
  IN OUT PCI_OPTROM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ConstructOptionRom (
  IN OUT PCI_OPTROM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateRomInjection (
  IN OUT PCI_OPTROM_CONTEXT  *Context
  );

VOID
EFIAPI
LogPciOptRomStatus (
  IN     PCI_OPTROM_CONTEXT  *Context
  );

#endif // PCI_OPTION_ROM_H_
