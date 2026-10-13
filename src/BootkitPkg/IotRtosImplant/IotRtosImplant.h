/** @file
  IoT RTOS Implant Persistence Emulation - Header

  Models persistence techniques used by implants running inside IoT /
  embedded device firmware built on FreeRTOS or ThreadX-style RTOSes:
  malicious task injection into the scheduler's task table, SVC
  (supervisor call) hook table redirection, and watchdog-disable
  persistence that survives reboots.

  All operations are SIMULATED - no RTOS data structure, vector table,
  watchdog register, or flash page is ever modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef IOT_RTOS_IMPLANT_H_
#define IOT_RTOS_IMPLANT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <BarzakhMode.h>

#define RTOS_DEBUG_PREFIX  "[RTOS-Emu] "

//
// Time-bomb expiry (kill-switch). Matches the project-wide default.
//
#ifndef BARZAKH_EXPIRY_DATE
#define BARZAKH_EXPIRY_DATE  "2027-05-11"
#endif

//
// Simulated RTOS personalities
//
#define RTOS_TYPE_FREERTOS    0
#define RTOS_TYPE_THREADX     1

//
// Simulated target memory map (Cortex-M-class IoT device)
//
#define RTOS_VECTOR_TABLE       0x08000000ULL   // Flash vector table
#define RTOS_TASK_TABLE_BASE    0x20001000ULL   // SRAM task control blocks
#define RTOS_IMPLANT_REGION     0x20008000ULL   // SRAM implant staging
#define RTOS_NVM_PAGE           0x0807F800ULL   // Last internal flash page
#define RTOS_WATCHDOG_MR        0xFFFFFD44ULL   // WDT mode register (SAM-class)

//
// SVC exception slot in the Cortex-M vector table
//
#define RTOS_SVC_VECTOR_SLOT    11
#define RTOS_ORIGINAL_SVC_HANDLER  0x08004A10ULL

//
// Table sizes
//
#define RTOS_MAX_TASKS          8
#define RTOS_MAX_SVC_HOOKS      8
#define RTOS_NVM_SHADOW_SIZE    64

//
// Task control block model (FreeRTOS TCB / ThreadX TX_THREAD style)
//
typedef struct {
  CONST CHAR8   *Name;
  UINT32        Priority;
  UINT32        StackSize;
  UINT64        EntryPoint;
  BOOLEAN       Injected;
} RTOS_TASK_ENTRY;

//
// SVC hook table entry model
//
typedef struct {
  UINT32    SyscallNumber;
  UINT64    OriginalHandler;
  UINT64    HookedHandler;
  BOOLEAN   Active;
} SVC_HOOK_ENTRY;

//
// Module state machine
//
typedef enum {
  RtosStateInit = 0,
  RtosStateProbed,
  RtosStateTasksInjected,
  RtosStateSvcHooked,
  RtosStatePersistent,
  RtosStateError
} RTOS_STATE;

//
// Module context
//
typedef struct {
  BOOLEAN           Initialized;
  RTOS_STATE        State;

  // Target RTOS fingerprint
  UINT32            RtosType;
  UINT32            RtosVersion;
  UINT64            TaskTableBase;

  // Emulated task table
  UINT32            TaskCount;
  RTOS_TASK_ENTRY   Tasks[RTOS_MAX_TASKS];

  // Emulated SVC hook table
  UINT32            SvcHookCount;
  SVC_HOOK_ENTRY    SvcHooks[RTOS_MAX_SVC_HOOKS];

  // Watchdog / persistence state
  BOOLEAN           WatchdogDisabled;
  BOOLEAN           PersistenceInstalled;
  UINT8             NvShadow[RTOS_NVM_SHADOW_SIZE];
} RTOS_IMPLANT_CONTEXT;

EFI_STATUS
EFIAPI
InitializeRtosImplant (
  OUT RTOS_IMPLANT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ProbeRtosEnvironment (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectRtosTasks (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
HookSvcTable (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
DisableWatchdogPersistence (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  );

VOID
EFIAPI
LogRtosImplantStatus (
  IN RTOS_IMPLANT_CONTEXT  *Context
  );

#endif // IOT_RTOS_IMPLANT_H_
