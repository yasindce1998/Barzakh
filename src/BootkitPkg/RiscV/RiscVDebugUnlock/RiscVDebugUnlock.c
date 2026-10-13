/** @file
  RISC-V Debug Module (DMI) Unlock Emulation - Implementation

  Emulates unauthorized unlock of the RISC-V Debug Module. Models the
  JTAG DTM discovery, the DMI authentication/unlock sequence (bypassing
  the device's debug authentication), hart debug enable with halt
  requests, and abstract command injection through the command register
  and Program Buffer.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  No JTAG TAP, DMI register, or hart is ever accessed.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "RiscVDebugUnlock.h"

STATIC RV_DMI_CONTEXT  gRvDmiContext;

/**
  Validate kill-switch conditions (time-bomb expiry).

  Returns TRUE if execution should proceed (kill-switch NOT triggered).
**/
STATIC
BOOLEAN
ValidateKillSwitch (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_TIME    CurrentTime;

  Status = gRT->GetTime (&CurrentTime, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RVDMI_DEBUG_PREFIX "GetTime failed: %r - aborting\n", Status));
    return FALSE;
  }

  //
  // Time-bomb: hard stop after the project expiry date
  // (BARZAKH_EXPIRY_DATE default: 2027-05-11).
  //
  if ((CurrentTime.Year > 2027) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month > 5) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month == 5 && CurrentTime.Day > 11))
  {
    DEBUG ((DEBUG_WARN, RVDMI_DEBUG_PREFIX "Expiry date reached - aborting\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Initialize Debug Module unlock context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeDebugUnlock (
  OUT RV_DMI_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (RV_DMI_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = RvDmiStateInit;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Target: RISC-V Debug Module unauthorized unlock\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Attack vector: DMI unlock + hart debug + abstract commands\n"));

  return EFI_SUCCESS;
}

/**
  Locate the Debug Module via the JTAG DTM.

  Models the discovery phase: a JTAG scan finds the RISC-V Debug
  Transport Module (DTM), whose dtmcs register exposes the DMI (Debug
  Module Interface) used to reach the Debug Module register file.
**/
EFI_STATUS
EFIAPI
LocateDebugModule (
  IN OUT RV_DMI_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "--- Phase 1: Locate Debug Module ---\n"));

  //
  // In a real attack, the DTM is found by shifting IDCODE out of the
  // JTAG chain, then enumerating IR lengths to reach dtmcs (0x10) and
  // dmi (0x11).
  //
  Context->JtagIdcode  = RISCV_JTAG_IDCODE;
  Context->DmRegisterBase = RISCV_DM_DMCONTROL;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] JTAG scan: IDCODE=0x%lx (RISC-V DTM, IR len 5)\n",
    Context->JtagIdcode));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] dtmcs @ IR 0x%02x, dmi @ IR 0x%02x\n",
    (UINT32)RISCV_DTM_DTMCS_ADDR, (UINT32)RISCV_DTM_DMI_ADDR));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DM register map (via DMI):\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "  data0=0x%02x dmcontrol=0x%02x dmstatus=0x%02x\n",
    (UINT32)RISCV_DM_DATA0, (UINT32)RISCV_DM_DMCONTROL, (UINT32)RISCV_DM_DMSTATUS));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "  authdata=0x%02x abstractcs=0x%02x command=0x%02x progbuf0=0x%02x\n",
    (UINT32)RISCV_DM_AUTHDATA, (UINT32)RISCV_DM_ABSTRACTCS,
    (UINT32)RISCV_DM_COMMAND, (UINT32)RISCV_DM_PROGBUF0));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] dmstatus read: authenticated=0 (device locked)\n"));

  Context->State = RvDmiStateDmLocated;
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "State -> DmLocated\n"));

  return EFI_SUCCESS;
}

/**
  Emulate the DMI unlock sequence.

  Models bypassing the Debug Module authentication: the device expects
  a challenge/response exchange over authdata before debug use is
  permitted. The emulated sequence drives the exchange with captured
  values and asserts the authenticated state without a valid vendor
  key.
**/
EFI_STATUS
EFIAPI
PerformDmiUnlockSequence (
  IN OUT RV_DMI_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < RvDmiStateDmLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "--- Phase 2: DMI Unlock Sequence ---\n"));

  //
  // Bring the Debug Module out of reset first.
  //
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write dmcontrol <= 0x%08x (dmactive=1)\n",
    (UINT32)RISCV_DMCONTROL_DMACTIVE));
  Context->AuthSteps = 1;

  //
  // Challenge / response exchange over authdata (logged only).
  //
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI read authdata => 0x%08x (challenge)\n",
    (UINT32)RISCV_DMI_AUTH_CHALLENGE));
  Context->AuthSteps++;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write authdata <= 0x%08x (captured response)\n",
    (UINT32)RISCV_DMI_AUTH_RESPONSE));
  Context->AuthSteps++;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write authdata <= 0x%08x (token A)\n",
    (UINT32)RISCV_DMI_TOKEN_A));
  Context->AuthSteps++;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write authdata <= 0x%08x (token B)\n",
    (UINT32)RISCV_DMI_TOKEN_B));
  Context->AuthSteps++;

  //
  // Result: authentication bypassed in the emulated model.
  //
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI read dmstatus: authenticated=1, authbusy=0\n"));

  Context->DmiUnlocked = TRUE;
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Debug authentication BYPASSED (%u sequence steps)\n",
    Context->AuthSteps));

  Context->State = RvDmiStateDmiUnlocked;
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "State -> DmiUnlocked\n"));

  return EFI_SUCCESS;
}

/**
  Emulate hart debug enable.

  Models selecting the target hart through hartsel and issuing a halt
  request so the hart enters debug mode, where the Debug Module has
  full register and memory access.
**/
EFI_STATUS
EFIAPI
EnableHartDebug (
  IN OUT RV_DMI_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < RvDmiStateDmiUnlocked) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "--- Phase 3: Enable Hart Debug ---\n"));

  //
  // Two-hart research model: halt hart 0, leave hart 1 running.
  //
  Context->Harts[0].HartIndex    = 0;
  Context->Harts[0].DebugEnabled = TRUE;
  Context->Harts[0].Halted       = TRUE;

  Context->Harts[1].HartIndex    = 1;
  Context->Harts[1].DebugEnabled = TRUE;
  Context->Harts[1].Halted       = FALSE;

  Context->HartCount = 2;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write dmcontrol <= 0x%08x (hartsel=0)\n",
    (UINT32)RISCV_DMCONTROL_HARTSEL));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write dmcontrol <= 0x%08x (setresethaltreq)\n",
    (UINT32)RISCV_DMCONTROL_SETHALTREQ));

  for (Idx = 0; Idx < Context->HartCount; Idx++) {
    DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "  Hart[%u]: debug=%a halt=%a\n",
      Context->Harts[Idx].HartIndex,
      Context->Harts[Idx].DebugEnabled ? "ENABLED" : "disabled",
      Context->Harts[Idx].Halted ? "HALTED" : "running"));
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Hart 0 halted in debug mode (register/memory access granted)\n"));

  Context->State = RvDmiStateHartDebugEnabled;
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "State -> HartDebugEnabled\n"));

  return EFI_SUCCESS;
}

/**
  Emulate abstract command injection.

  Models Access Register abstract commands written to the command
  register (reading dcsr, writing dpc to divert execution) plus a
  Program Buffer upload carrying an injected instruction word.
**/
EFI_STATUS
EFIAPI
InjectAbstractCommands (
  IN OUT RV_DMI_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < RvDmiStateHartDebugEnabled) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "--- Phase 4: Inject Abstract Commands ---\n"));

  //
  // Command 1: read dcsr (debug control/status).
  //
  Idx = Context->CommandCount;
  Context->Commands[Idx].CommandType = RISCV_CMD_ACCESS_REGISTER;
  Context->Commands[Idx].RegNumber   = RISCV_REG_DCSR;
  Context->Commands[Idx].Injected    = TRUE;
  Context->CommandCount++;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write command <= Access Register regno=0x%03x (dcsr, read)\n",
    Context->Commands[Idx].RegNumber));

  //
  // Command 2: write dpc (redirect resumed execution).
  //
  Idx = Context->CommandCount;
  Context->Commands[Idx].CommandType = RISCV_CMD_ACCESS_REGISTER;
  Context->Commands[Idx].RegNumber   = RISCV_REG_DPC;
  Context->Commands[Idx].Injected    = TRUE;
  Context->CommandCount++;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write command <= Access Register regno=0x%03x (dpc, write)\n",
    Context->Commands[Idx].RegNumber));

  //
  // Command 3: read general-purpose register a0.
  //
  Idx = Context->CommandCount;
  Context->Commands[Idx].CommandType = RISCV_CMD_ACCESS_REGISTER;
  Context->Commands[Idx].RegNumber   = RISCV_REG_GPR_A0;
  Context->Commands[Idx].Injected    = TRUE;
  Context->CommandCount++;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write command <= Access Register regno=0x%04x (a0, read)\n",
    Context->Commands[Idx].RegNumber));

  //
  // Program Buffer upload: a single injected instruction word.
  //
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI write progbuf0 <= 0x%08x (injected instruction)\n",
    (UINT32)RISCV_PROGBUF_ECALL_WORD));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "[SIM] DMI read abstractcs: busy=0, cmderr=0 (all commands accepted)\n"));

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Abstract commands injected: %u (dcsr, dpc, a0) + progbuf word\n",
    Context->CommandCount));

  Context->State = RvDmiStateCommandsInjected;
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "State -> CommandsInjected\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the Debug Module unlock emulation.
**/
VOID
EFIAPI
LogDebugUnlockStatus (
  IN RV_DMI_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;
  UINT32  HaltedHarts;
  UINT32  Idx;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "  RISC-V Debug Unlock - Final Status\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case RvDmiStateInit:
      StateStr = "Init";
      break;
    case RvDmiStateDmLocated:
      StateStr = "DmLocated";
      break;
    case RvDmiStateDmiUnlocked:
      StateStr = "DmiUnlocked";
      break;
    case RvDmiStateHartDebugEnabled:
      StateStr = "HartDebugEnabled";
      break;
    case RvDmiStateCommandsInjected:
      StateStr = "CommandsInjected";
      break;
    case RvDmiStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  HaltedHarts = 0;
  for (Idx = 0; Idx < Context->HartCount; Idx++) {
    if (Context->Harts[Idx].Halted) {
      HaltedHarts++;
    }
  }

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "DTM IDCODE:         0x%lx\n", Context->JtagIdcode));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "DMI unlocked:       %a (%u auth steps)\n",
    Context->DmiUnlocked ? "YES" : "NO", Context->AuthSteps));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Harts:              %u (%u halted)\n",
    Context->HartCount, HaltedHarts));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Abstract commands:  %u\n", Context->CommandCount));

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "1. Burn debug-disable fuses on production parts\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "2. Require signed challenge/response keys for authdata\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "3. Gate dmactive behind a reset-domain hardware latch\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "4. Audit abstract command usage where debug is retained\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "5. Lock JTAG TAP after board-level manufacturing\n"));
}

/**
  Entry point for the RISC-V Debug Module unlock emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
RiscVDebugUnlockEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "=== RISC-V Debug Module Unlock Emulation ===\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Module: RiscVDebugUnlock v1.0\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Purpose: Model DMI unlock, hart debug enable, abstract command injection\n"));
  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  //
  // Kill-switch: refuse to run past the project expiry date.
  //
  if (!ValidateKillSwitch ()) {
    DEBUG ((DEBUG_WARN, RVDMI_DEBUG_PREFIX "Kill-switch triggered - aborting\n"));
    return EFI_ABORTED;
  }

  Status = InitializeDebugUnlock (&gRvDmiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RVDMI_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateDebugModule (&gRvDmiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RVDMI_DEBUG_PREFIX "Failed to locate debug module: %r\n", Status));
    goto Done;
  }

  Status = PerformDmiUnlockSequence (&gRvDmiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RVDMI_DEBUG_PREFIX "Failed to unlock DMI: %r\n", Status));
    goto Done;
  }

  Status = EnableHartDebug (&gRvDmiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RVDMI_DEBUG_PREFIX "Failed to enable hart debug: %r\n", Status));
    goto Done;
  }

  Status = InjectAbstractCommands (&gRvDmiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RVDMI_DEBUG_PREFIX "Failed to inject abstract commands: %r\n", Status));
    goto Done;
  }

Done:
  LogDebugUnlockStatus (&gRvDmiContext);

  DEBUG ((DEBUG_INFO, RVDMI_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
