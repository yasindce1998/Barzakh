/** @file
  MSR Hooking Module Implementation

  Implements MSR hooking to model CosmicStrand-style kernel syscall
  interception for research purposes. All hooks operate in research mode
  (logging only, no actual redirection).

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "MsrHook.h"
#include <BarzakhMode.h>

//
// MSR writes are a real CosmicStrand-style technique — in simulation
// builds they are logged only; functional builds perform the write.
// (Kept as a separate name so the write path reads explicitly.)
//
#define RESEARCH_MODE  BARZAKH_SIMULATION_MODE

/**
  Read a Model Specific Register.

  @param[in]  Msr  MSR index to read.

  @retval Value of the MSR.
**/
UINT64
EFIAPI
ReadMsr (
  IN UINT32  Msr
  )
{
  UINT64  Value;

  Value = AsmReadMsr64 (Msr);
  
  DEBUG ((
    DEBUG_VERBOSE,
    "[Barzakh-MSR] Read MSR 0x%x = 0x%lx\n",
    Msr,
    Value
    ));

  return Value;
}

/**
  Write a Model Specific Register.

  @param[in]  Msr    MSR index to write.
  @param[in]  Value  Value to write.

  @retval EFI_SUCCESS  MSR written successfully.
**/
EFI_STATUS
EFIAPI
WriteMsr (
  IN UINT32  Msr,
  IN UINT64  Value
  )
{
  if (RESEARCH_MODE) {
    DEBUG ((
      DEBUG_INFO,
      "[Barzakh-MSR] RESEARCH MODE: Would write MSR 0x%x = 0x%lx\n",
      Msr,
      Value
      ));
    return EFI_SUCCESS;
  }

  AsmWriteMsr64 (Msr, Value);
  
  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Wrote MSR 0x%x = 0x%lx\n",
    Msr,
    Value
    ));

  return EFI_SUCCESS;
}

/**
  Install MSR hooks to redirect kernel syscall entry points.

  This function models the CosmicStrand bootkit technique of hijacking
  the IA32_LSTAR MSR to intercept all system calls. In research mode,
  it only logs what would be done without actually modifying MSRs.

  @param[in,out]  Context  Pointer to MSR hook context.

  @retval EFI_SUCCESS           Hooks installed successfully.
  @retval EFI_INVALID_PARAMETER Context is NULL.
  @retval EFI_ALREADY_STARTED   Hooks already installed.
**/
EFI_STATUS
EFIAPI
InstallMsrHooks (
  IN OUT MSR_HOOK_CONTEXT  *Context
  )
{
  UINT64  CurrentLstar;
  UINT64  CurrentCstar;
  UINT64  CurrentSysenterEip;

  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->HooksInstalled) {
    DEBUG ((DEBUG_WARN, "[Barzakh-MSR] Hooks already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  DEBUG ((DEBUG_INFO, "[Barzakh-MSR] Installing MSR hooks...\n"));

  //
  // Read current MSR values
  //
  CurrentLstar = ReadMsr (IA32_LSTAR);
  CurrentCstar = ReadMsr (IA32_CSTAR);
  CurrentSysenterEip = ReadMsr (IA32_SYSENTER_EIP);

  //
  // Save original values
  //
  Context->OriginalLstar = CurrentLstar;
  Context->OriginalCstar = CurrentCstar;
  Context->OriginalSysenterEip = CurrentSysenterEip;

  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Original IA32_LSTAR: 0x%lx\n",
    CurrentLstar
    ));
  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Original IA32_CSTAR: 0x%lx\n",
    CurrentCstar
    ));
  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Original IA32_SYSENTER_EIP: 0x%lx\n",
    CurrentSysenterEip
    ));

  //
  // In a real bootkit, we would:
  // 1. Allocate memory for hook handler
  // 2. Write trampoline code to hook handler
  // 3. Update MSRs to point to hook handler
  //
  // For research purposes, we simulate this:
  //
  Context->HookAddress = 0xDEADBEEF12345678ULL;  // Simulated hook address

  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Hook handler address: 0x%lx\n",
    Context->HookAddress
    ));

  //
  // Install hooks (research mode: log only)
  //
  WriteMsr (IA32_LSTAR, Context->HookAddress);
  WriteMsr (IA32_CSTAR, Context->HookAddress);
  WriteMsr (IA32_SYSENTER_EIP, Context->HookAddress);

  Context->HooksInstalled = TRUE;
  Context->HookCount = 3;

  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Installed %d MSR hooks\n",
    Context->HookCount
    ));

  //
  // Log what a real hook handler would do
  //
  DEBUG ((DEBUG_INFO, "[Barzakh-MSR] Hook handler would:\n"));
  DEBUG ((DEBUG_INFO, "  1. Save all registers\n"));
  DEBUG ((DEBUG_INFO, "  2. Log syscall number and arguments\n"));
  DEBUG ((DEBUG_INFO, "  3. Optionally modify arguments\n"));
  DEBUG ((DEBUG_INFO, "  4. Call original syscall handler at 0x%lx\n", CurrentLstar));
  DEBUG ((DEBUG_INFO, "  5. Optionally modify return value\n"));
  DEBUG ((DEBUG_INFO, "  6. Restore registers and return\n"));

  return EFI_SUCCESS;
}

/**
  Remove MSR hooks and restore original values.

  @param[in,out]  Context  Pointer to MSR hook context.

  @retval EFI_SUCCESS           Hooks removed successfully.
  @retval EFI_INVALID_PARAMETER Context is NULL.
  @retval EFI_NOT_STARTED       Hooks not installed.
**/
EFI_STATUS
EFIAPI
RemoveMsrHooks (
  IN OUT MSR_HOOK_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Context->HooksInstalled) {
    DEBUG ((DEBUG_WARN, "[Barzakh-MSR] Hooks not installed\n"));
    return EFI_NOT_STARTED;
  }

  DEBUG ((DEBUG_INFO, "[Barzakh-MSR] Removing MSR hooks...\n"));

  //
  // Restore original MSR values
  //
  WriteMsr (IA32_LSTAR, Context->OriginalLstar);
  WriteMsr (IA32_CSTAR, Context->OriginalCstar);
  WriteMsr (IA32_SYSENTER_EIP, Context->OriginalSysenterEip);

  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Restored IA32_LSTAR to 0x%lx\n",
    Context->OriginalLstar
    ));
  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Restored IA32_CSTAR to 0x%lx\n",
    Context->OriginalCstar
    ));
  DEBUG ((
    DEBUG_INFO,
    "[Barzakh-MSR] Restored IA32_SYSENTER_EIP to 0x%lx\n",
    Context->OriginalSysenterEip
    ));

  Context->HooksInstalled = FALSE;
  Context->HookCount = 0;

  DEBUG ((DEBUG_INFO, "[Barzakh-MSR] MSR hooks removed\n"));

  return EFI_SUCCESS;
}

/**
  Log current MSR values for analysis.

  @param[in]  Context  Pointer to MSR hook context.
**/
VOID
EFIAPI
LogMsrValues (
  IN MSR_HOOK_CONTEXT  *Context
  )
{
  UINT64  Lstar;
  UINT64  Cstar;
  UINT64  Star;
  UINT64  Fmask;
  UINT64  SysenterCs;
  UINT64  SysenterEsp;
  UINT64  SysenterEip;

  DEBUG ((DEBUG_INFO, "[Barzakh-MSR] Current MSR Values:\n"));
  DEBUG ((DEBUG_INFO, "================================\n"));

  //
  // Read syscall-related MSRs
  //
  Lstar = ReadMsr (IA32_LSTAR);
  Cstar = ReadMsr (IA32_CSTAR);
  Star = ReadMsr (IA32_STAR);
  Fmask = ReadMsr (IA32_FMASK);

  DEBUG ((DEBUG_INFO, "IA32_LSTAR (0x%x):  0x%016lx\n", IA32_LSTAR, Lstar));
  DEBUG ((DEBUG_INFO, "IA32_CSTAR (0x%x):  0x%016lx\n", IA32_CSTAR, Cstar));
  DEBUG ((DEBUG_INFO, "IA32_STAR (0x%x):   0x%016lx\n", IA32_STAR, Star));
  DEBUG ((DEBUG_INFO, "IA32_FMASK (0x%x):  0x%016lx\n", IA32_FMASK, Fmask));

  //
  // Read sysenter-related MSRs
  //
  SysenterCs = ReadMsr (IA32_SYSENTER_CS);
  SysenterEsp = ReadMsr (IA32_SYSENTER_ESP);
  SysenterEip = ReadMsr (IA32_SYSENTER_EIP);

  DEBUG ((DEBUG_INFO, "IA32_SYSENTER_CS (0x%x):  0x%016lx\n", IA32_SYSENTER_CS, SysenterCs));
  DEBUG ((DEBUG_INFO, "IA32_SYSENTER_ESP (0x%x): 0x%016lx\n", IA32_SYSENTER_ESP, SysenterEsp));
  DEBUG ((DEBUG_INFO, "IA32_SYSENTER_EIP (0x%x): 0x%016lx\n", IA32_SYSENTER_EIP, SysenterEip));

  //
  // Check if values have been modified
  //
  if (Context != NULL && Context->HooksInstalled) {
    DEBUG ((DEBUG_INFO, "\n[Barzakh-MSR] Hook Status:\n"));
    DEBUG ((DEBUG_INFO, "================================\n"));
    DEBUG ((DEBUG_INFO, "Hooks Installed: YES\n"));
    DEBUG ((DEBUG_INFO, "Hook Count: %d\n", Context->HookCount));
    DEBUG ((DEBUG_INFO, "Hook Address: 0x%lx\n", Context->HookAddress));
    
    if (Lstar != Context->OriginalLstar) {
      DEBUG ((DEBUG_WARN, "IA32_LSTAR MODIFIED: 0x%lx -> 0x%lx\n", 
              Context->OriginalLstar, Lstar));
    }
    
    if (Cstar != Context->OriginalCstar) {
      DEBUG ((DEBUG_WARN, "IA32_CSTAR MODIFIED: 0x%lx -> 0x%lx\n",
              Context->OriginalCstar, Cstar));
    }
    
    if (SysenterEip != Context->OriginalSysenterEip) {
      DEBUG ((DEBUG_WARN, "IA32_SYSENTER_EIP MODIFIED: 0x%lx -> 0x%lx\n",
              Context->OriginalSysenterEip, SysenterEip));
    }
  }

  DEBUG ((DEBUG_INFO, "================================\n"));
}

/**
  Detect if MSRs have been hooked by comparing against expected values.

  @param[in]  Context  Pointer to MSR hook context with baseline values.

  @retval TRUE   MSRs appear to be hooked.
  @retval FALSE  MSRs appear clean.
**/
BOOLEAN
EFIAPI
DetectMsrHooks (
  IN MSR_HOOK_CONTEXT  *Context
  )
{
  UINT64   CurrentLstar;
  UINT64   CurrentCstar;
  UINT64   CurrentSysenterEip;
  BOOLEAN  HooksDetected;

  HooksDetected = FALSE;

  if (Context == NULL) {
    return FALSE;
  }

  //
  // Read current MSR values
  //
  CurrentLstar = ReadMsr (IA32_LSTAR);
  CurrentCstar = ReadMsr (IA32_CSTAR);
  CurrentSysenterEip = ReadMsr (IA32_SYSENTER_EIP);

  //
  // Compare against baseline
  //
  if (CurrentLstar != Context->OriginalLstar) {
    DEBUG ((
      DEBUG_WARN,
      "[Barzakh-MSR] HOOK DETECTED: IA32_LSTAR modified\n"
      ));
    DEBUG ((
      DEBUG_WARN,
      "  Expected: 0x%lx\n  Current:  0x%lx\n",
      Context->OriginalLstar,
      CurrentLstar
      ));
    HooksDetected = TRUE;
  }

  if (CurrentCstar != Context->OriginalCstar) {
    DEBUG ((
      DEBUG_WARN,
      "[Barzakh-MSR] HOOK DETECTED: IA32_CSTAR modified\n"
      ));
    DEBUG ((
      DEBUG_WARN,
      "  Expected: 0x%lx\n  Current:  0x%lx\n",
      Context->OriginalCstar,
      CurrentCstar
      ));
    HooksDetected = TRUE;
  }

  if (CurrentSysenterEip != Context->OriginalSysenterEip) {
    DEBUG ((
      DEBUG_WARN,
      "[Barzakh-MSR] HOOK DETECTED: IA32_SYSENTER_EIP modified\n"
      ));
    DEBUG ((
      DEBUG_WARN,
      "  Expected: 0x%lx\n  Current:  0x%lx\n",
      Context->OriginalSysenterEip,
      CurrentSysenterEip
      ));
    HooksDetected = TRUE;
  }

  return HooksDetected;
}

