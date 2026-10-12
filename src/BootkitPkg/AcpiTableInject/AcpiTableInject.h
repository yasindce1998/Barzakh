/** @file
  ACPI Table Injection Emulation - Header

  Models malicious SSDT injection with AML bytecode. Constructs custom SSDT
  tables containing OperationRegion(SystemMemory) for kernel memory access,
  and installs them via EFI_ACPI_TABLE_PROTOCOL.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ACPI_TABLE_INJECT_H_
#define ACPI_TABLE_INJECT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <IndustryStandard/Acpi.h>
#include <BarzakhMode.h>

#define ACPI_DEBUG_PREFIX  "[AcpiInject-Emu] "

//
// SSDT signature and OEM fields
//
#define SSDT_SIGNATURE               0x54445353  // "SSDT"
#define SSDT_OEM_ID                  "BARZAK"
#define SSDT_OEM_TABLE_ID            0x4B494C414D  // "MALKI" reversed
#define SSDT_OEM_REVISION            0x00000001
#define SSDT_CREATOR_ID              0x4C544E49  // "INTL"
#define SSDT_CREATOR_REVISION        0x20200110

//
// AML opcodes used in payload (guarded to avoid conflict with MdePkg ACPI headers)
//
#ifndef AML_SCOPE_OP
#define AML_SCOPE_OP                 0x10
#endif
#ifndef AML_NAME_OP
#define AML_NAME_OP                  0x08
#endif
#ifndef AML_OPREGION_OP
#define AML_OPREGION_OP              0x80
#endif
#ifndef AML_EXT_PREFIX
#define AML_EXT_PREFIX               0x5B
#endif
#ifndef AML_EXT_OPREGION_OP
#define AML_EXT_OPREGION_OP          0x80
#endif
#ifndef AML_FIELD_OP
#define AML_FIELD_OP                 0x81
#endif
#ifndef AML_METHOD_OP
#define AML_METHOD_OP                0x14
#endif
#ifndef AML_RETURN_OP
#define AML_RETURN_OP                0xA4
#endif
#ifndef AML_ZERO_OP
#define AML_ZERO_OP                  0x00
#endif
#ifndef AML_ONE_OP
#define AML_ONE_OP                   0x01
#endif
#ifndef AML_BYTE_PREFIX
#define AML_BYTE_PREFIX              0x0A
#endif
#ifndef AML_WORD_PREFIX
#define AML_WORD_PREFIX              0x0B
#endif
#ifndef AML_DWORD_PREFIX
#define AML_DWORD_PREFIX             0x0C
#endif
#ifndef AML_QWORD_PREFIX
#define AML_QWORD_PREFIX             0x0E
#endif
#ifndef AML_STRING_PREFIX
#define AML_STRING_PREFIX            0x0D
#endif

//
// OperationRegion address spaces
//
#define AML_REGION_SYSTEM_MEMORY     0x00
#define AML_REGION_SYSTEM_IO         0x01
#define AML_REGION_PCI_CONFIG        0x02

//
// Maximum AML payload size
//
#define MAX_AML_PAYLOAD_SIZE         512
#define MAX_SSDT_SIZE                (sizeof(EFI_ACPI_DESCRIPTION_HEADER) + MAX_AML_PAYLOAD_SIZE)

typedef enum {
  AcpiStateUninitialized = 0,
  AcpiStateProtocolLocated,
  AcpiStateSsdtConstructed,
  AcpiStateTableInstalled,
  AcpiStatePayloadActive
} ACPI_INJECT_STATE;

typedef struct {
  BOOLEAN           Initialized;
  ACPI_INJECT_STATE State;

  // ACPI protocol
  BOOLEAN           ProtocolFound;
  VOID              *AcpiProtocol;

  // SSDT construction
  UINT8             *SsdtBuffer;
  UINT32            SsdtSize;
  UINT32            AmlPayloadSize;
  BOOLEAN           SsdtReady;

  // Installation state
  UINTN             TableKey;
  BOOLEAN           TableInstalled;

  // Payload details
  UINT64            TargetRegionBase;
  UINT32            TargetRegionSize;
  BOOLEAN           OperationRegionCreated;
} ACPI_INJECT_CONTEXT;

EFI_STATUS
EFIAPI
InitializeAcpiInject (
  OUT ACPI_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateAcpiProtocol (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ConstructMaliciousSsdt (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateTableInstallation (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateAmlExecution (
  IN OUT ACPI_INJECT_CONTEXT  *Context
  );

VOID
EFIAPI
LogAcpiInjectStatus (
  IN     ACPI_INJECT_CONTEXT  *Context
  );

#endif // ACPI_TABLE_INJECT_H_
