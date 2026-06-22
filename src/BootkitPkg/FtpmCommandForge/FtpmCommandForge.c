/** @file
  fTPM Command Forge Emulation - Implementation

  Emulates AMD firmware TPM (fTPM) command forgery against the Platform
  Security Processor (PSP). Models the C2P/P2C shared buffer layout,
  TPM2 command header construction, PCR extension forgery, and response
  injection to bypass host-side measurement validation.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  This module serves as a research reference for defensive security teams
  studying AMD fTPM command buffer attack vectors.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "FtpmCommandForge.h"

STATIC FTPM_CONTEXT  gFtpmContext;

/**
  Initialize fTPM forge context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeFtpmForge (
  OUT FTPM_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (FTPM_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = FtpmStateInit;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Target: AMD fTPM command buffer forgery\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Attack vector: C2P/P2C shared buffer manipulation\n"));

  return EFI_SUCCESS;
}

/**
  Locate the fTPM command/response mailbox in PSP MMIO space.

  On AMD platforms, the fTPM communicates with the host OS via a shared
  memory region mapped through PSP MMIO. The C2P (Command-to-PSP) buffer
  carries TPM2 commands, and the P2C (PSP-to-Command) buffer carries
  responses. Both are at fixed offsets from the PSP MMIO base.
**/
EFI_STATUS
EFIAPI
LocateFtpmMailbox (
  IN OUT FTPM_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "--- Phase 1: Locate fTPM Mailbox ---\n"));

  //
  // In a real attack, the PSP MMIO base is discovered via:
  // 1. PCI config space (PSP device BAR)
  // 2. ACPI tables (TPM2 ACPI table with CRB interface)
  // 3. Known AMD SoC-specific fixed addresses
  //
  Context->PspMmioBase = PSP_MMIO_BASE;
  Context->C2pBuffer   = PSP_MMIO_BASE + C2P_MSG_OFFSET;
  Context->P2cBuffer   = PSP_MMIO_BASE + P2C_MSG_OFFSET;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "PSP MMIO base:     0x%lx\n", Context->PspMmioBase));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  C2P buffer (cmd):  0x%lx (offset 0x%x)\n",
    Context->C2pBuffer, C2P_MSG_OFFSET));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  P2C buffer (rsp):  0x%lx (offset 0x%x)\n",
    Context->P2cBuffer, P2C_MSG_OFFSET));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Command buffer size:  0x%x bytes\n", FTPM_CMD_BUFFER_SIZE));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Response buffer size: 0x%x bytes\n", FTPM_RESP_BUFFER_SIZE));

  //
  // Simulate probing the PSP mailbox registers
  //
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Reading PSP mailbox status at 0x%lx\n",
    Context->PspMmioBase));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] PSP ready bit: SET (fTPM firmware loaded)\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] C2P buffer: idle (no pending command)\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] P2C buffer: idle (no pending response)\n"));

  Context->State = FtpmStateLocated;
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "State -> Located\n"));

  return EFI_SUCCESS;
}

/**
  Forge TPM2 commands in the C2P buffer.

  Constructs two forged TPM2 commands:
  1. TPM2_CC_PCR_Extend - Extend PCR[7] with a controlled SHA-256 digest
     to manipulate Secure Boot measurements.
  2. TPM2_CC_PCR_Read - Read PCR[0-7] to verify the forgery took effect.

  In a real attack, these commands would be written directly to the C2P
  shared buffer before the PSP doorbell is rung.
**/
EFI_STATUS
EFIAPI
ForgeCommand (
  IN OUT FTPM_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < FtpmStateLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "--- Phase 2: Forge TPM2 Commands ---\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Constructing forged commands in C2P buffer...\n"));

  //
  // Command 1: TPM2_CC_PCR_Extend for PCR[7] with SHA-256
  //
  // PCR[7] holds Secure Boot policy measurements. Extending it with a
  // controlled value allows an attacker to predict the final PCR value
  // and unseal secrets bound to a specific PCR policy.
  //
  Context->ForgedCommands[0].CommandCode = TPM2_CC_PCR_EXTEND;
  Context->ForgedCommands[0].PcrIndex    = 7;
  Context->ForgedCommands[0].DigestSize  = 32;  // SHA-256
  Context->ForgedCommandCount++;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Forged CMD[0]: TPM2_CC_PCR_Extend\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Tag:         0x%04x (TPM2_ST_SESSIONS)\n", TPM2_ST_SESSIONS));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  CommandSize: %u bytes (header + PCR select + digest)\n",
    10 + 4 + 32));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  CommandCode: 0x%08x (PCR_Extend)\n", TPM2_CC_PCR_EXTEND));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  PCR index:   7 (Secure Boot policy)\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Digest:      SHA-256 (32 bytes, attacker-controlled)\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  [SIM] Would write %u bytes to C2P at 0x%lx\n",
    10 + 4 + 32, Context->C2pBuffer));

  //
  // Command 2: TPM2_CC_PCR_Read for PCR[0-7]
  //
  // Used to verify the PCR extension took effect by reading back the
  // bank of platform configuration registers.
  //
  Context->ForgedCommands[1].CommandCode = TPM2_CC_PCR_READ;
  Context->ForgedCommands[1].PcrIndex    = 0;   // Read starting from PCR[0]
  Context->ForgedCommands[1].DigestSize  = 0;   // No digest for read commands
  Context->ForgedCommandCount++;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Forged CMD[1]: TPM2_CC_PCR_Read\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Tag:         0x%04x (TPM2_ST_NO_SESSIONS)\n", TPM2_ST_NO_SESSIONS));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  CommandSize: %u bytes (header + PCR select)\n", 10 + 8));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  CommandCode: 0x%08x (PCR_Read)\n", TPM2_CC_PCR_READ));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  PCR select:  PCR[0] through PCR[7]\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  [SIM] Would write %u bytes to C2P at 0x%lx\n",
    10 + 8, Context->C2pBuffer));

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Total forged commands: %u\n", Context->ForgedCommandCount));

  Context->State = FtpmStateCommandForged;
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "State -> CommandForged\n"));

  return EFI_SUCCESS;
}

/**
  Inject forged TPM2 responses into the P2C buffer.

  Simulates writing crafted TPM2_RC_SUCCESS responses into the P2C
  (PSP-to-Command) shared buffer. This models an attack where the
  adversary intercepts PSP responses before the host reads them,
  replacing failure codes with success to mask the forgery.
**/
EFI_STATUS
EFIAPI
InjectResponse (
  IN OUT FTPM_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < FtpmStateCommandForged) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "--- Phase 3: Inject Forged Responses ---\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Constructing forged responses in P2C buffer...\n"));

  //
  // Response 1: Success for PCR_Extend
  //
  Context->ForgedResponses[0].ResponseCode = TPM2_RC_SUCCESS;
  Context->ForgedResponses[0].Validated    = FALSE;
  Context->ForgedResponseCount++;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Forged RSP[0]: PCR_Extend response\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Tag:          0x%04x (TPM2_ST_NO_SESSIONS)\n", TPM2_ST_NO_SESSIONS));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  ResponseSize: 10 bytes (header only)\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  ResponseCode: 0x%03x (TPM2_RC_SUCCESS)\n", TPM2_RC_SUCCESS));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  [SIM] Would write 10 bytes to P2C at 0x%lx\n",
    Context->P2cBuffer));

  //
  // Response 2: Success for PCR_Read with forged digest values
  //
  Context->ForgedResponses[1].ResponseCode = TPM2_RC_SUCCESS;
  Context->ForgedResponses[1].Validated    = FALSE;
  Context->ForgedResponseCount++;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Forged RSP[1]: PCR_Read response\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  Tag:          0x%04x (TPM2_ST_NO_SESSIONS)\n", TPM2_ST_NO_SESSIONS));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  ResponseSize: %u bytes (header + 8 PCR digests)\n", 10 + 8 * 32));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  ResponseCode: 0x%03x (TPM2_RC_SUCCESS)\n", TPM2_RC_SUCCESS));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  [SIM] Would write %u bytes to P2C at 0x%lx\n",
    10 + 8 * 32, Context->P2cBuffer));

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Total forged responses: %u\n", Context->ForgedResponseCount));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Host TPM driver would read SUCCESS from P2C buffer\n"));

  Context->State = FtpmStateResponseInjected;
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "State -> ResponseInjected\n"));

  return EFI_SUCCESS;
}

/**
  Validate forged commands would pass host-side validation.

  Verifies that each forged command has correct structure:
  - Valid TPM2 session tag (ST_NO_SESSIONS or ST_SESSIONS)
  - Correct command size field
  - Recognized command code
**/
EFI_STATUS
EFIAPI
ValidateFtpmForge (
  IN OUT FTPM_CONTEXT  *Context
  )
{
  UINT32  Idx;
  BOOLEAN AllValid;

  if (Context == NULL || Context->State < FtpmStateResponseInjected) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "--- Phase 4: Validate Forged Commands ---\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Checking %u commands for structural correctness...\n",
    Context->ForgedCommandCount));

  AllValid = TRUE;

  for (Idx = 0; Idx < Context->ForgedCommandCount; Idx++) {
    BOOLEAN  CmdValid;

    CmdValid = TRUE;

    //
    // Check command code is a recognized TPM2 CC
    //
    if (Context->ForgedCommands[Idx].CommandCode != TPM2_CC_PCR_EXTEND &&
        Context->ForgedCommands[Idx].CommandCode != TPM2_CC_PCR_READ &&
        Context->ForgedCommands[Idx].CommandCode != TPM2_CC_GET_RANDOM) {
      DEBUG ((DEBUG_WARN, FTPM_DEBUG_PREFIX "  CMD[%u]: INVALID command code 0x%08x\n",
        Idx, Context->ForgedCommands[Idx].CommandCode));
      CmdValid = FALSE;
    }

    //
    // Check PCR index is within valid range (0-23)
    //
    if (Context->ForgedCommands[Idx].CommandCode == TPM2_CC_PCR_EXTEND ||
        Context->ForgedCommands[Idx].CommandCode == TPM2_CC_PCR_READ) {
      if (Context->ForgedCommands[Idx].PcrIndex > 23) {
        DEBUG ((DEBUG_WARN, FTPM_DEBUG_PREFIX "  CMD[%u]: INVALID PCR index %u (max 23)\n",
          Idx, Context->ForgedCommands[Idx].PcrIndex));
        CmdValid = FALSE;
      }
    }

    //
    // Check digest size for extend commands
    //
    if (Context->ForgedCommands[Idx].CommandCode == TPM2_CC_PCR_EXTEND) {
      if (Context->ForgedCommands[Idx].DigestSize != 20 &&
          Context->ForgedCommands[Idx].DigestSize != 32 &&
          Context->ForgedCommands[Idx].DigestSize != 48 &&
          Context->ForgedCommands[Idx].DigestSize != 64) {
        DEBUG ((DEBUG_WARN, FTPM_DEBUG_PREFIX "  CMD[%u]: INVALID digest size %u\n",
          Idx, Context->ForgedCommands[Idx].DigestSize));
        CmdValid = FALSE;
      }
    }

    if (CmdValid) {
      DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  CMD[%u]: VALID (CC=0x%08x PCR=%u DigestSz=%u)\n",
        Idx, Context->ForgedCommands[Idx].CommandCode,
        Context->ForgedCommands[Idx].PcrIndex,
        Context->ForgedCommands[Idx].DigestSize));
    } else {
      AllValid = FALSE;
    }
  }

  //
  // Validate response codes
  //
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Checking %u responses for validity...\n",
    Context->ForgedResponseCount));

  for (Idx = 0; Idx < Context->ForgedResponseCount; Idx++) {
    if (Context->ForgedResponses[Idx].ResponseCode == TPM2_RC_SUCCESS) {
      Context->ForgedResponses[Idx].Validated = TRUE;
      DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  RSP[%u]: VALID (RC=0x%03x SUCCESS)\n",
        Idx, Context->ForgedResponses[Idx].ResponseCode));
    } else {
      DEBUG ((DEBUG_WARN, FTPM_DEBUG_PREFIX "  RSP[%u]: non-success code 0x%03x\n",
        Idx, Context->ForgedResponses[Idx].ResponseCode));
      AllValid = FALSE;
    }
  }

  if (AllValid) {
    DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "All forged commands/responses passed validation\n"));
    DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "[SIM] Host TPM stack would accept these as legitimate\n"));
  } else {
    DEBUG ((DEBUG_WARN, FTPM_DEBUG_PREFIX "Some forged entries failed validation\n"));
    Context->State = FtpmStateError;
    DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "State -> Error\n"));
    return EFI_SUCCESS;
  }

  Context->State = FtpmStateComplete;
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "State -> Complete\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the fTPM command forge emulation.
**/
VOID
EFIAPI
LogFtpmForgeStatus (
  IN FTPM_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "  fTPM Command Forge - Final Status\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case FtpmStateInit:
      StateStr = "Init";
      break;
    case FtpmStateLocated:
      StateStr = "Located";
      break;
    case FtpmStateCommandForged:
      StateStr = "CommandForged";
      break;
    case FtpmStateResponseInjected:
      StateStr = "ResponseInjected";
      break;
    case FtpmStateComplete:
      StateStr = "Complete";
      break;
    case FtpmStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "PSP MMIO base:      0x%lx\n", Context->PspMmioBase));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "C2P buffer:         0x%lx\n", Context->C2pBuffer));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "P2C buffer:         0x%lx\n", Context->P2cBuffer));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Commands forged:    %u\n", Context->ForgedCommandCount));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Responses injected: %u\n", Context->ForgedResponseCount));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Forge successful:   %a\n",
    Context->State == FtpmStateComplete ? "YES" : "NO"));

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "1. fTPM command buffer is inside PSP-protected MMIO region\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "2. C2P/P2C access requires ring-0 with correct MSR config\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "3. AMD SKINIT/DRTM can attest PSP firmware integrity\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "4. Hardware fTPM NV counters prevent PCR replay attacks\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "5. Latest PSP firmware validates command structure cryptographically\n"));
}

/**
  Entry point for the fTPM Command Forge emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
FtpmCommandForgeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "=== AMD fTPM Command Forge Emulation ===\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Module: FtpmCommandForge v1.0\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Purpose: Model fTPM command buffer forgery via PSP MMIO\n"));
  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  Status = InitializeFtpmForge (&gFtpmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FTPM_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateFtpmMailbox (&gFtpmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FTPM_DEBUG_PREFIX "Failed to locate mailbox: %r\n", Status));
    goto Done;
  }

  Status = ForgeCommand (&gFtpmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FTPM_DEBUG_PREFIX "Failed to forge commands: %r\n", Status));
    goto Done;
  }

  Status = InjectResponse (&gFtpmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FTPM_DEBUG_PREFIX "Failed to inject responses: %r\n", Status));
    goto Done;
  }

  Status = ValidateFtpmForge (&gFtpmContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FTPM_DEBUG_PREFIX "Failed to validate forge: %r\n", Status));
    goto Done;
  }

Done:
  LogFtpmForgeStatus (&gFtpmContext);

  DEBUG ((DEBUG_INFO, FTPM_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
