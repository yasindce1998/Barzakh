/** @file
  Device Tree Blob Injection Emulation - Header

  Models FDT (Flattened Device Tree) manipulation attacks. Parses the
  device tree structure, locates target nodes, and injects malicious
  device bindings that cause attacker firmware to be loaded at boot.

  All operations are SIMULATED - no actual device tree is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef DEVICE_TREE_INJECT_H_
#define DEVICE_TREE_INJECT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define DTI_DEBUG_PREFIX  "[DTInject-Emu] "

//
// FDT (Flattened Device Tree) magic and structure tokens
//
#define FDT_MAGIC              0xD00DFEED
#define FDT_VERSION            17
#define FDT_LAST_COMP_VER     16

//
// FDT structure block tokens (big-endian on wire, stored native here)
//
#define FDT_BEGIN_NODE         0x00000001
#define FDT_END_NODE           0x00000002
#define FDT_PROP               0x00000003
#define FDT_NOP                0x00000004
#define FDT_END                0x00000009

//
// Simulated DTB location and sizes
//
#define DTI_DTB_BASE_ADDR      0x40000000
#define DTI_DTB_MAX_SIZE       0x00100000  // 1MB max DTB
#define DTI_DTB_ORIGINAL_SIZE  0x00020000  // 128KB original
#define DTI_INJECT_OFFSET      0x0001F000  // Inject near end of struct block

//
// Maximum tracked nodes and properties
//
#define DTI_MAX_NODES          32
#define DTI_MAX_PROPERTIES     16
#define DTI_MAX_NAME_LEN       64
#define DTI_MAX_VALUE_LEN      256

//
// Simulated FDT header (40 bytes, matches real FDT header layout)
//
typedef struct {
  UINT32    Magic;
  UINT32    TotalSize;
  UINT32    OffDtStruct;
  UINT32    OffDtStrings;
  UINT32    OffMemRsvmap;
  UINT32    Version;
  UINT32    LastCompVersion;
  UINT32    BootCpuidPhys;
  UINT32    SizeDtStrings;
  UINT32    SizeDtStruct;
} DTI_FDT_HEADER;

//
// Device tree node descriptor
//
typedef struct {
  CHAR8     Name[DTI_MAX_NAME_LEN];
  UINT32    Offset;
  UINT32    Depth;
  UINT32    NumProperties;
  BOOLEAN   IsTarget;
} DTI_NODE_INFO;

//
// Device tree property descriptor
//
typedef struct {
  CHAR8     Name[DTI_MAX_NAME_LEN];
  UINT32    Length;
  UINT32    NameOffset;
  UINT8     Value[DTI_MAX_VALUE_LEN];
} DTI_PROPERTY_INFO;

//
// Injected node payload
//
typedef struct {
  CHAR8             NodeName[DTI_MAX_NAME_LEN];
  CHAR8             Compatible[DTI_MAX_VALUE_LEN];
  UINT64            RegBase;
  UINT64            RegSize;
  CHAR8             FirmwareName[DTI_MAX_NAME_LEN];
  UINT32            InjectedOffset;
  UINT32            InjectedSize;
} DTI_INJECT_PAYLOAD;

typedef enum {
  DtiStateUninitialized = 0,
  DtiStateDtbLocated,
  DtiStateDtbParsed,
  DtiStateNodeInjected,
  DtiStateDtbInstalled
} DTI_STATE;

typedef struct {
  BOOLEAN           Initialized;
  DTI_STATE         State;

  // DTB location and header
  UINT64            DtbBase;
  DTI_FDT_HEADER    Header;

  // Parsed nodes
  DTI_NODE_INFO     Nodes[DTI_MAX_NODES];
  UINT32            NodeCount;

  // Injection state
  DTI_INJECT_PAYLOAD  Payload;
  UINT32            NewTotalSize;
  BOOLEAN           DtbModified;
} DTI_CONTEXT;

EFI_STATUS
EFIAPI
InitializeDeviceTreeInject (
  OUT DTI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateDeviceTree (
  IN OUT DTI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ParseDeviceTree (
  IN OUT DTI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectMaliciousNode (
  IN OUT DTI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InstallModifiedDtb (
  IN OUT DTI_CONTEXT  *Context
  );

VOID
EFIAPI
LogDeviceTreeInjectStatus (
  IN     DTI_CONTEXT  *Context
  );

#endif // DEVICE_TREE_INJECT_H_
