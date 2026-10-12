/** @file
  SMM Persistence Emulation - Header

  Models Ring -2 persistence techniques including SMRAM layout discovery,
  SMI handler implantation, and SMRAM lock bypass (D_LCK bit manipulation).

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SMM_PERSISTENCE_H_
#define SMM_PERSISTENCE_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/IoLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define SMM_DEBUG_PREFIX  "[SMM-Emu] "

//
// Intel MSR definitions for SMRR (System Management Range Register)
//
#define MSR_IA32_SMRR_PHYSBASE   0x1F2
#define MSR_IA32_SMRR_PHYSMASK   0x1F3

//
// SMI trigger port (APMC - Advanced Power Management Control)
//
#define SMI_TRIGGER_PORT         0xB2
#define SMI_STATUS_PORT          0xB3

//
// D_LCK bit in SMM control register (PCI B0:D0:F0 offset 0x9D)
//
#define SMM_DLOCK_PCI_BUS        0
#define SMM_DLOCK_PCI_DEV        0
#define SMM_DLOCK_PCI_FUNC       0
#define SMM_DLOCK_OFFSET         0x9D
#define SMM_DLOCK_BIT            BIT4

//
// TSEG (Top of Low Usable DRAM) defines
//
#define TSEG_DEFAULT_BASE        0x7F000000
#define TSEG_DEFAULT_SIZE        0x00800000  // 8 MB
#define SMRAM_HANDLER_OFFSET     0x00010000

//
// SMI command codes
//
#define SMI_CMD_IMPLANT_HANDLER  0xBA
#define SMI_CMD_TRIGGER_PAYLOAD  0xBB
#define SMI_CMD_STATUS_CHECK     0xBC

//
// Maximum SMI handlers we track
//
#define MAX_SMI_HANDLERS         8

typedef enum {
  SmmStateUninitialized = 0,
  SmmStateDiscovered,
  SmmStateLockBypassed,
  SmmStateHandlerInjected,
  SmmStateActive
} SMM_IMPLANT_STATE;

typedef struct {
  UINT8     CommandCode;
  UINT64    HandlerAddress;
  UINT32    HandlerSize;
  BOOLEAN   IsActive;
} SMI_HANDLER_ENTRY;

typedef struct {
  BOOLEAN            Initialized;
  SMM_IMPLANT_STATE  State;

  // SMRAM layout (discovered from SMRR MSRs)
  UINT64             TsegBase;
  UINT64             TsegSize;
  UINT64             SmrrPhysBase;
  UINT64             SmrrPhysMask;
  BOOLEAN            SmrrValid;

  // D_LCK bypass state
  BOOLEAN            DLockSet;
  BOOLEAN            DLockBypassed;

  // Implanted handlers
  SMI_HANDLER_ENTRY  Handlers[MAX_SMI_HANDLERS];
  UINT32             HandlerCount;

  // Simulated SMRAM buffer
  UINT8              *SimulatedSmram;
  UINT32             SimulatedSmramSize;
} SMM_PERSISTENCE_CONTEXT;

EFI_STATUS
EFIAPI
InitializeSmmPersistence (
  OUT SMM_PERSISTENCE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
DiscoverSmramLayout (
  IN OUT SMM_PERSISTENCE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateSmramLockBypass (
  IN OUT SMM_PERSISTENCE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectSmiHandler (
  IN OUT SMM_PERSISTENCE_CONTEXT  *Context,
  IN     UINT8                    CommandCode,
  IN     VOID                     *HandlerCode,
  IN     UINT32                   HandlerSize
  );

EFI_STATUS
EFIAPI
TriggerSmi (
  IN     SMM_PERSISTENCE_CONTEXT  *Context,
  IN     UINT8                    CommandCode
  );

VOID
EFIAPI
LogSmmPersistenceStatus (
  IN     SMM_PERSISTENCE_CONTEXT  *Context
  );

#endif // SMM_PERSISTENCE_H_
