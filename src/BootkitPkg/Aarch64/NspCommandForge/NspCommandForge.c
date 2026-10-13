/** @file
  NVIDIA Security Processor Command Forge Emulation - Implementation

  Emulates forged command traffic to the NVIDIA Security Processor
  (NSP). Models the secure command/response mailbox layout, response
  channel redirection to an attacker-controlled staging buffer, forged
  NSP command construction, and Security Engine keyslot dump emulation.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  This module serves as a research reference for defensive security
  teams studying NSP secure-mailbox and keyslot attack vectors, in the
  same spirit as FtpmCommandForge models AMD fTPM command forgery.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "NspCommandForge.h"

STATIC NSP_FORGE_CONTEXT  gNspForgeContext;

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
    DEBUG ((DEBUG_ERROR, NSP_DEBUG_PREFIX "GetTime failed: %r - aborting\n", Status));
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
    DEBUG ((DEBUG_WARN, NSP_DEBUG_PREFIX "Expiry date reached - aborting\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Initialize NSP forge context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeNspForge (
  OUT NSP_FORGE_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (NSP_FORGE_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = NspStateInit;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Target: NVIDIA Security Processor command forgery\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Attack vector: secure-mailbox redirect + keyslot dump\n"));

  return EFI_SUCCESS;
}

/**
  Locate the NSP secure mailbox in the SoC address map.

  The NSP communicates with the host SoC through a secure mailbox with
  separate command and response FIFO channels. Only the NSP (and code
  running below it) may service the keyslot table reachable through
  this mailbox.
**/
EFI_STATUS
EFIAPI
LocateNspSecureMailbox (
  IN OUT NSP_FORGE_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "--- Phase 1: Locate NSP Secure Mailbox ---\n"));

  //
  // In a real attack, the mailbox base is discovered via:
  // 1. Device tree / board file parsing (nsp-secure-mbox node)
  // 2. NSP firmware reverse engineering
  // 3. Known SoC-specific fixed addresses
  //
  Context->MboxBase  = NSP_MBOX_BASE;
  Context->CmdBuffer = NSP_MBOX_BASE + NSP_MBOX_CMD_OFFSET;
  Context->RspBuffer = NSP_MBOX_BASE + NSP_MBOX_RSP_OFFSET;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "NSP secure mailbox base: 0x%lx\n", Context->MboxBase));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  Command channel (host->NSP): 0x%lx\n", Context->CmdBuffer));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  Response channel (NSP->host): 0x%lx\n", Context->RspBuffer));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  Status register:              0x%lx\n",
    NSP_MBOX_BASE + NSP_MBOX_STATUS_OFFSET));

  //
  // Simulate reading mailbox status
  //
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Mailbox status: channels idle, doorbell armed\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Keyslot service reachable via opcode 0x%02x/0x%02x\n",
    (UINT32)NSP_CMD_KEYSLOT_READ, (UINT32)NSP_CMD_KEYSLOT_EXPORT));

  Context->State = NspStateMailboxLocated;
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "State -> MailboxLocated\n"));

  return EFI_SUCCESS;
}

/**
  Emulate secure-mailbox redirect.

  Models diverting the response channel so that replies (both genuine
  and forged) land in an attacker-controlled staging buffer that the
  implant reads before re-posting selective content to the host read
  path. This is the injection prerequisite: the host trusts whatever
  the redirected channel delivers.
**/
EFI_STATUS
EFIAPI
RedirectSecureMailbox (
  IN OUT NSP_FORGE_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < NspStateMailboxLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "--- Phase 2: Redirect Secure Mailbox ---\n"));

  Context->RedirectedRspBuffer = NSP_EXFIL_BUFFER;
  Context->MailboxRedirected   = TRUE;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Response pointer register: 0x%lx <= 0x%lx\n",
    Context->RspBuffer, Context->RedirectedRspBuffer));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] NSP responses now staged in attacker DRAM buffer\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  Host read path consumes the redirected channel unchanged\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  Forged responses can be injected at will from here\n"));

  Context->State = NspStateMailboxRedirected;
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "State -> MailboxRedirected\n"));

  return EFI_SUCCESS;
}

/**
  Emulate forged NSP command construction.

  Builds the command records the implant would post on the command
  channel: a benign version probe (to learn firmware layout), then
  keyslot read/export requests against a target Security Engine slot.
**/
EFI_STATUS
EFIAPI
ForgeNspCommands (
  IN OUT NSP_FORGE_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < NspStateMailboxRedirected) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "--- Phase 3: Forge NSP Commands ---\n"));

  //
  // In a real attack, commands are forged by writing a command word
  // sequence into the command FIFO and ringing the doorbell; the NSP
  // cannot distinguish the forged post from a genuine driver request.
  //

  // Command 1: benign version probe (reconnaissance)
  Idx = Context->ForgedCommandCount;
  Context->ForgedCommands[Idx].Opcode       = NSP_CMD_GET_VERSION;
  Context->ForgedCommands[Idx].KeyslotIndex = 0;
  Context->ForgedCommands[Idx].KeySize      = 0;
  Context->ForgedCommands[Idx].Forged       = TRUE;
  Context->ForgedCommandCount++;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Post cmd: opcode=0x%02x GET_VERSION (recon)\n",
    Context->ForgedCommands[Idx].Opcode));

  // Command 2: keyslot metadata read
  Idx = Context->ForgedCommandCount;
  Context->ForgedCommands[Idx].Opcode       = NSP_CMD_KEYSLOT_READ;
  Context->ForgedCommands[Idx].KeyslotIndex = 4;
  Context->ForgedCommands[Idx].KeySize      = NSP_SIM_KEY_SIZE;
  Context->ForgedCommands[Idx].Forged       = TRUE;
  Context->ForgedCommandCount++;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Post cmd: opcode=0x%02x KEYSLOT_READ slot=%u\n",
    Context->ForgedCommands[Idx].Opcode, Context->ForgedCommands[Idx].KeyslotIndex));

  // Command 3: keyslot material export
  Idx = Context->ForgedCommandCount;
  Context->ForgedCommands[Idx].Opcode       = NSP_CMD_KEYSLOT_EXPORT;
  Context->ForgedCommands[Idx].KeyslotIndex = 4;
  Context->ForgedCommands[Idx].KeySize      = NSP_SIM_KEY_SIZE;
  Context->ForgedCommands[Idx].Forged       = TRUE;
  Context->ForgedCommandCount++;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Post cmd: opcode=0x%02x KEYSLOT_EXPORT slot=%u\n",
    Context->ForgedCommands[Idx].Opcode, Context->ForgedCommands[Idx].KeyslotIndex));

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Forged commands posted: %u (version probe, read, export)\n",
    Context->ForgedCommandCount));

  Context->State = NspStateCommandsForged;
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "State -> CommandsForged\n"));

  return EFI_SUCCESS;
}

/**
  Emulate the keyslot dump.

  Simulates the NSP servicing the forged export: keyslot material is
  returned through the redirected response channel into the staging
  buffer. The bytes below are deterministic stand-ins - no real key
  exists anywhere in this module.
**/
EFI_STATUS
EFIAPI
EmulateKeyslotDump (
  IN OUT NSP_FORGE_CONTEXT  *Context
  )
{
  UINT32  Idx;
  UINT32  ByteIdx;

  if (Context == NULL || Context->State < NspStateCommandsForged) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "--- Phase 4: Emulate Keyslot Dump ---\n"));

  Context->KeyslotCount = 0;

  for (Idx = 0; Idx < Context->ForgedCommandCount && Context->KeyslotCount < NSP_MAX_KEYSLOTS; Idx++) {
    if (Context->ForgedCommands[Idx].Opcode != NSP_CMD_KEYSLOT_EXPORT) {
      continue;
    }

    Context->Keyslots[Context->KeyslotCount].SlotIndex =
      (UINT8)Context->ForgedCommands[Idx].KeyslotIndex;
    Context->Keyslots[Context->KeyslotCount].KeySize =
      Context->ForgedCommands[Idx].KeySize;

    //
    // Deterministic simulated key material (research placeholder).
    //
    for (ByteIdx = 0; ByteIdx < NSP_SIM_KEY_SIZE; ByteIdx++) {
      Context->Keyslots[Context->KeyslotCount].KeyData[ByteIdx] =
        (UINT8)(0xA5 ^ (ByteIdx + Context->ForgedCommands[Idx].KeyslotIndex));
    }

    Context->Keyslots[Context->KeyslotCount].Dumped = TRUE;
    Context->KeyslotCount++;
  }

  if (Context->KeyslotCount > 0) {
    DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Dumped %u keyslot(s) via redirected response channel:\n",
      Context->KeyslotCount));

    for (Idx = 0; Idx < Context->KeyslotCount; Idx++) {
      DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  Slot[%u]: ID=%u Len=%u bytes\n",
        Idx, Context->Keyslots[Idx].SlotIndex, Context->Keyslots[Idx].KeySize));
      DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "    First 8 bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
        Context->Keyslots[Idx].KeyData[0], Context->Keyslots[Idx].KeyData[1],
        Context->Keyslots[Idx].KeyData[2], Context->Keyslots[Idx].KeyData[3],
        Context->Keyslots[Idx].KeyData[4], Context->Keyslots[Idx].KeyData[5],
        Context->Keyslots[Idx].KeyData[6], Context->Keyslots[Idx].KeyData[7]));
    }

    DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "[SIM] Exfil vector: staging buffer at 0x%lx\n",
      Context->RedirectedRspBuffer));
  } else {
    DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "No keyslot export commands were forged\n"));
  }

  Context->State = NspStateKeyslotsDumped;
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "State -> KeyslotsDumped\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the NSP command forge emulation.
**/
VOID
EFIAPI
LogNspForgeStatus (
  IN NSP_FORGE_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "  NSP Command Forge - Final Status\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case NspStateInit:
      StateStr = "Init";
      break;
    case NspStateMailboxLocated:
      StateStr = "MailboxLocated";
      break;
    case NspStateMailboxRedirected:
      StateStr = "MailboxRedirected";
      break;
    case NspStateCommandsForged:
      StateStr = "CommandsForged";
      break;
    case NspStateKeyslotsDumped:
      StateStr = "KeyslotsDumped";
      break;
    case NspStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Mailbox base:       0x%lx\n", Context->MboxBase));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Mailbox redirected: %a\n",
    Context->MailboxRedirected ? "YES" : "NO"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Commands forged:    %u\n", Context->ForgedCommandCount));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Keyslots dumped:    %u\n", Context->KeyslotCount));

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "1. Mailbox pointer registers must be write-locked after boot\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "2. NSP commands need per-origin authentication (session MACs)\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "3. Keyslot export should be fused off in production parts\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "4. Rate-limit and audit keyslot service commands\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "5. Attest NSP firmware state from the host before key ops\n"));
}

/**
  Entry point for the NSP command forge emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
NspCommandForgeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "=== NSP Command Forge Emulation ===\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Module: NspCommandForge v1.0\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Purpose: Model forged NSP commands and keyslot dump\n"));
  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  //
  // Kill-switch: refuse to run past the project expiry date.
  //
  if (!ValidateKillSwitch ()) {
    DEBUG ((DEBUG_WARN, NSP_DEBUG_PREFIX "Kill-switch triggered - aborting\n"));
    return EFI_ABORTED;
  }

  Status = InitializeNspForge (&gNspForgeContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, NSP_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateNspSecureMailbox (&gNspForgeContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, NSP_DEBUG_PREFIX "Failed to locate mailbox: %r\n", Status));
    goto Done;
  }

  Status = RedirectSecureMailbox (&gNspForgeContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, NSP_DEBUG_PREFIX "Failed to redirect mailbox: %r\n", Status));
    goto Done;
  }

  Status = ForgeNspCommands (&gNspForgeContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, NSP_DEBUG_PREFIX "Failed to forge commands: %r\n", Status));
    goto Done;
  }

  Status = EmulateKeyslotDump (&gNspForgeContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, NSP_DEBUG_PREFIX "Failed to dump keyslots: %r\n", Status));
    goto Done;
  }

Done:
  LogNspForgeStatus (&gNspForgeContext);

  DEBUG ((DEBUG_INFO, NSP_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
