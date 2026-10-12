/** @file
  EL3 Secure Monitor Persistence Emulation - Header

  Models ARM EL3 secure monitor persistence: SMC handler injection,
  PSCI function interception, SCR_EL3 manipulation. ARM's equivalent
  of x86 SMM-based persistence at the highest privilege level.

  All operations are SIMULATED - no actual ARM system registers are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef EL3_SECURE_MONITOR_H_
#define EL3_SECURE_MONITOR_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define EL3MON_DEBUG_PREFIX  "[EL3Mon-Emu] "

//
// ARM Exception Levels
//
#define ARM_EL0  0
#define ARM_EL1  1
#define ARM_EL2  2
#define ARM_EL3  3

//
// SCR_EL3 (Secure Configuration Register) bit fields
//
#define EL3_SCR_NS_BIT     BIT0   // Non-Secure bit (0=Secure, 1=Non-Secure)
#define EL3_SCR_IRQ_BIT    BIT1   // IRQ routing to EL3
#define EL3_SCR_FIQ_BIT    BIT2   // FIQ routing to EL3
#define EL3_SCR_EA_BIT     BIT3   // External Abort routing
#define EL3_SCR_SMD_BIT    BIT7   // SMC Disable (0=enabled, 1=disabled)
#define EL3_SCR_HCE_BIT    BIT8   // Hypervisor Call Enable
#define EL3_SCR_SIF_BIT    BIT9   // Secure Instruction Fetch
#define EL3_SCR_RW_BIT     BIT10  // Lower level is AArch64

//
// PSCI (Power State Coordination Interface) function IDs — SMC64 calling convention
//
#define PSCI_VERSION            0x84000000
#define PSCI_CPU_SUSPEND_64     0xC4000001
#define PSCI_CPU_OFF            0x84000002
#define PSCI_CPU_ON_64          0xC4000003
#define PSCI_AFFINITY_INFO_64   0xC4000004
#define PSCI_SYSTEM_OFF         0x84000008
#define PSCI_SYSTEM_RESET       0x84000009
#define PSCI_FEATURES           0x8400000A

//
// SMC calling convention
//
#define SMC_FAST_CALL_BIT       BIT31
#define SMC_64BIT_CALL_BIT      BIT30
#define SMC_SERVICE_MASK        0x3F000000
#define SMC_SERVICE_SHIFT       24
#define SMC_FUNC_MASK           0x0000FFFF

//
// SMC service ranges
//
#define SMC_SERVICE_ARCH        0   // ARM Architecture Calls
#define SMC_SERVICE_CPU         1   // CPU Service Calls
#define SMC_SERVICE_SIP         2   // SiP Service Calls
#define SMC_SERVICE_OEM         3   // OEM Service Calls
#define SMC_SERVICE_STD         4   // Standard Service Calls

//
// Simulated secure monitor memory layout
//
#define EL3_MONITOR_BASE        0x0E000000
#define EL3_MONITOR_SIZE        0x00100000  // 1MB
#define EL3_HANDLER_TABLE_OFF   0x00001000
#define EL3_MAX_HANDLERS        16

//
// PSCI handler table entry
//
typedef struct {
  UINT32    FunctionId;
  UINT64    HandlerAddress;
  BOOLEAN   Intercepted;
  UINT32    CallCount;
} EL3_PSCI_HANDLER;

//
// Simulated SMC context (registers passed via SMC)
//
typedef struct {
  UINT64    X0;   // Function ID (W0 for SMC32)
  UINT64    X1;   // Arg1 (target CPU MPIDR for CPU_ON)
  UINT64    X2;   // Arg2 (entry point for CPU_ON)
  UINT64    X3;   // Arg3 (context ID for CPU_ON)
} EL3_SMC_CONTEXT;

typedef enum {
  El3StateUninitialized = 0,
  El3StateScmDiscovered,
  El3StatePsciIntercepted,
  El3StateHandlerInjected,
  El3StateActive
} EL3_MONITOR_STATE;

typedef struct {
  BOOLEAN            Initialized;
  EL3_MONITOR_STATE  State;

  // SCR_EL3 emulation
  UINT64             ScrEl3Value;
  BOOLEAN            SecureWorldActive;

  // PSCI handler table
  EL3_PSCI_HANDLER   PsciHandlers[EL3_MAX_HANDLERS];
  UINT32             HandlerCount;
  UINT32             InterceptedCount;

  // Injection state
  UINT64             InjectedHandlerAddr;
  BOOLEAN            HandlerInjected;
  UINT32             SmcCallsProcessed;
} EL3_MONITOR_CONTEXT;

EFI_STATUS
EFIAPI
InitializeEl3Monitor (
  OUT EL3_MONITOR_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
DiscoverSecureMonitor (
  IN OUT EL3_MONITOR_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InterceptPsciHandlers (
  IN OUT EL3_MONITOR_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectSmcHandler (
  IN OUT EL3_MONITOR_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateSmcCall (
  IN OUT EL3_MONITOR_CONTEXT  *Context,
  IN     EL3_SMC_CONTEXT      *SmcArgs
  );

VOID
EFIAPI
LogEl3MonitorStatus (
  IN     EL3_MONITOR_CONTEXT  *Context
  );

#endif // EL3_SECURE_MONITOR_H_
