/** @file
  RISC-V Debug Module (DMI) Unlock Emulation - Header

  Models unauthorized unlock of the RISC-V Debug Module: the DMI
  (Debug Module Interface) unlock sequence, hart debug enable with
  halt request, and abstract command injection through the command
  register and Program Buffer.

  All operations are SIMULATED - no JTAG TAP, DMI register, or debug
  module is ever accessed.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef RISCV_DEBUG_UNLOCK_H_
#define RISCV_DEBUG_UNLOCK_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <BarzakhMode.h>

#define RVDMI_DEBUG_PREFIX  "[RV-DMI-Emu] "

//
// Time-bomb expiry (kill-switch). Matches the project-wide default.
//
#ifndef BARZAKH_EXPIRY_DATE
#define BARZAKH_EXPIRY_DATE  "2027-05-11"
#endif

//
// JTAG DTM register addresses (RISC-V debug spec)
//
#define RISCV_DTM_DTMCS_ADDR        0x10
#define RISCV_DTM_DMI_ADDR          0x11
#define RISCV_JTAG_IDCODE           0x20000A93ULL   // Simulated RISC-V DTM IDCODE

//
// Debug Module register offsets (via DMI)
//
#define RISCV_DM_DATA0              0x04
#define RISCV_DM_DMCONTROL          0x10
#define RISCV_DM_DMSTATUS           0x11
#define RISCV_DM_AUTHDATA           0x12
#define RISCV_DM_ABSTRACTCS         0x16
#define RISCV_DM_COMMAND            0x17
#define RISCV_DM_PROGBUF0           0x20

//
// dmcontrol bits (research model)
//
#define RISCV_DMCONTROL_DMACTIVE    BIT0
#define RISCV_DMCONTROL_HARTSEL     0x03FF0000
#define RISCV_DMCONTROL_HALTREQ     BIT31
#define RISCV_DMCONTROL_SETHALTREQ  BIT30

//
// Simulated DMI unlock sequence (challenge / response words)
//
#define RISCV_DMI_AUTH_CHALLENGE    0x5A3C91F7
#define RISCV_DMI_AUTH_RESPONSE     0x2E7B04D8
#define RISCV_DMI_TOKEN_A           0x00000001
#define RISCV_DMI_TOKEN_B           0x9E3779B9

//
// Hart / command table sizes
//
#define RISCV_DM_MAX_HARTS          4
#define RISCV_DM_MAX_COMMANDS       8

//
// Hart debug state model
//
typedef struct {
  UINT32    HartIndex;
  BOOLEAN   DebugEnabled;
  BOOLEAN   Halted;
} RISCV_HART_STATE;

//
// Abstract command model
//
typedef struct {
  UINT32    CommandType;
  UINT32    RegNumber;
  BOOLEAN   Injected;
} RISCV_ABSTRACT_COMMAND;

//
// Abstract command types (research model)
//
#define RISCV_CMD_ACCESS_REGISTER   0x02
#define RISCV_CMD_QUICK_ACCESS      0x01

//
// Simulated CSR / register numbers
//
#define RISCV_REG_DCSR              0x300
#define RISCV_REG_DPC               0x301
#define RISCV_REG_GPR_A0            0x1000

//
// Simulated Program Buffer instruction (c.ecall stand-in encoding)
//
#define RISCV_PROGBUF_ECALL_WORD    0x00100073

//
// Module state machine
//
typedef enum {
  RvDmiStateInit = 0,
  RvDmiStateDmLocated,
  RvDmiStateDmiUnlocked,
  RvDmiStateHartDebugEnabled,
  RvDmiStateCommandsInjected,
  RvDmiStateError
} RV_DMI_STATE;

//
// Module context
//
typedef struct {
  BOOLEAN                 Initialized;
  RV_DMI_STATE            State;

  // Debug Module discovery
  UINT64                  JtagIdcode;
  UINT32                  DmRegisterBase;

  // Unlock state
  BOOLEAN                 DmiUnlocked;
  UINT32                  AuthSteps;

  // Hart debug state
  UINT32                  HartCount;
  RISCV_HART_STATE        Harts[RISCV_DM_MAX_HARTS];

  // Abstract command state
  UINT32                  CommandCount;
  RISCV_ABSTRACT_COMMAND  Commands[RISCV_DM_MAX_COMMANDS];
} RV_DMI_CONTEXT;

EFI_STATUS
EFIAPI
InitializeDebugUnlock (
  OUT RV_DMI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateDebugModule (
  IN OUT RV_DMI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
PerformDmiUnlockSequence (
  IN OUT RV_DMI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EnableHartDebug (
  IN OUT RV_DMI_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectAbstractCommands (
  IN OUT RV_DMI_CONTEXT  *Context
  );

VOID
EFIAPI
LogDebugUnlockStatus (
  IN RV_DMI_CONTEXT  *Context
  );

#endif // RISCV_DEBUG_UNLOCK_H_
