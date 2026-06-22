/** @file
  HECI Intercept Emulation - Header

  Models Host Embedded Controller Interface (HECI) bus traffic interception
  between the host CPU and Intel Management Engine (ME). HECI is the primary
  communication channel used by Intel ME for host-side messaging (MKHI, ICC,
  dynamic client registration).

  All operations are SIMULATED - no actual HECI hardware is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef HECI_INTERCEPT_H_
#define HECI_INTERCEPT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define SIMULATION_MODE  TRUE

#define HECI_DEBUG_PREFIX  "[HECI-Emu] "

//
// HECI PCI device location (B0:D22:F0)
//
#define HECI_PCI_BUS    0
#define HECI_PCI_DEV    22
#define HECI_PCI_FUN    0

//
// HECI MMIO BAR and register offsets
//
#define HECI_MBAR           0x10
#define H_CSR_OFFSET        0x04   // Host Control/Status Register
#define ME_CSR_OFFSET       0x0C   // ME Control/Status Register
#define H_CB_WW_OFFSET      0x00   // Host Circular Buffer Write Window
#define ME_CB_RW_OFFSET     0x08   // ME Circular Buffer Read Window
#define HECI_MMIO_SIZE      0x1000

//
// HECI message group IDs
//
#define HECI_GROUP_MKHI         0xFF   // ME Kernel Host Interface
#define HECI_GROUP_ICC          0x04   // Integrated Clock Controller
#define HECI_GROUP_HECI_CLIENT  0x01   // Fixed HECI client
#define HECI_GROUP_DYN_CLIENT   0x02   // Dynamic client registration

//
// HECI message structure
//
typedef struct {
  UINT8     GroupId;
  UINT8     Command;
  UINT8     HostAddr;
  UINT8     MeAddr;
  UINT32    Length;
  UINT8     Data[64];
} HECI_MESSAGE;

//
// Maximum intercepted messages and exfiltrated payloads
//
#define HECI_MAX_INTERCEPTED    16
#define HECI_MAX_EXFILTRATED    8

//
// HECI intercept state machine
//
typedef enum {
  HeciStateInit = 0,
  HeciStateLocated,
  HeciStateMapped,
  HeciStateIntercepting,
  HeciStateComplete,
  HeciStateError
} HECI_STATE;

//
// HECI intercept context
//
typedef struct {
  BOOLEAN       Initialized;
  HECI_STATE    State;

  // Device MMIO
  UINT64        HeciMmioBase;
  UINT32        HCsr;
  UINT32        MeCsr;
  UINT64        CircularBufferBase;

  // Intercepted messages
  HECI_MESSAGE  InterceptedMessages[HECI_MAX_INTERCEPTED];
  UINT32        InterceptedCount;

  // Exfiltrated payloads
  HECI_MESSAGE  ExfiltratedPayloads[HECI_MAX_EXFILTRATED];
  UINT32        ExfiltratedCount;
} HECI_CONTEXT;

EFI_STATUS
EFIAPI
InitializeHeciIntercept (
  OUT HECI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateHeciDevice (
  IN OUT HECI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
MapHeciRegisters (
  IN OUT HECI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InterceptHeciMessages (
  IN OUT HECI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ExfiltrateHeciPayloads (
  IN OUT HECI_CONTEXT  *Context
  );

VOID
EFIAPI
LogHeciInterceptStatus (
  IN HECI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
HeciInterceptEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // HECI_INTERCEPT_H_
