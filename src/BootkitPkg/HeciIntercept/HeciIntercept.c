/** @file
  HECI Intercept Emulation - Implementation

  Emulates Host Embedded Controller Interface (HECI) bus traffic interception
  between the host CPU and Intel Management Engine (ME). Models PCI device
  enumeration, MMIO register mapping, circular buffer snooping, and HECI
  message parsing for MKHI, ICC, and dynamic client traffic.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  This module serves as a research reference for defensive security teams
  studying Intel ME communication attack vectors.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "HeciIntercept.h"

STATIC HECI_CONTEXT  gHeciContext;

/**
  Initialize HECI intercept context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeHeciIntercept (
  OUT HECI_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (HECI_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = HeciStateInit;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Target: Intel HECI bus traffic interception\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Attack vector: Host<->ME circular buffer snooping\n"));

  return EFI_SUCCESS;
}

/**
  Locate the HECI PCI device (B0:D22:F0) and read its BAR0.

  The HECI device is Intel ME's primary host-side interface, exposed as a
  PCI device at Bus 0, Device 22, Function 0. The MMIO base address is
  obtained from BAR0 (offset 0x10).
**/
EFI_STATUS
EFIAPI
LocateHeciDevice (
  IN OUT HECI_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "--- Phase 1: Locate HECI Device ---\n"));

  //
  // In a real attack, the HECI device is located via:
  // 1. PCI configuration space enumeration (B0:D22:F0)
  // 2. Reading BAR0 (MBAR) at config offset 0x10
  // 3. Verifying VID/DID matches Intel ME controller
  //
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Enumerating PCI bus %d, device %d, function %d\n",
    HECI_PCI_BUS, HECI_PCI_DEV, HECI_PCI_FUN));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Reading PCI config VID/DID...\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] VID=0x8086 DID=0xA13A (Intel ME HECI Controller)\n"));

  //
  // Simulate reading BAR0 from PCI config space
  //
  Context->HeciMmioBase = 0xFED1A000ULL;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Reading BAR0 at config offset 0x%02x\n", HECI_MBAR));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] HECI MMIO base: 0x%lx\n", Context->HeciMmioBase));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] MMIO region size: 0x%x bytes\n", HECI_MMIO_SIZE));

  Context->State = HeciStateLocated;
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "State -> Located\n"));

  return EFI_SUCCESS;
}

/**
  Map HECI MMIO registers (H_CSR, ME_CSR, circular buffers).

  Once the MMIO base is known, the Host and ME Control/Status Registers
  are mapped, along with the circular buffer windows used for message
  exchange.
**/
EFI_STATUS
EFIAPI
MapHeciRegisters (
  IN OUT HECI_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < HeciStateLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "--- Phase 2: Map HECI Registers ---\n"));

  //
  // In a real scenario, we would map the MMIO region and read:
  // - H_CSR: host-side control/status (interrupt enable, reset, ready)
  // - ME_CSR: ME-side control/status (ME ready, buffer depth, pointers)
  // - Circular buffer read/write windows for message exchange
  //
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Mapping H_CSR at MMIO+0x%02x\n", H_CSR_OFFSET));
  Context->HCsr = 0x80000401;  // Host ready, interrupt enabled, buffer depth=4
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] H_CSR value: 0x%08x (HostReady=1, IntEn=1, Depth=4)\n",
    Context->HCsr));

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Mapping ME_CSR at MMIO+0x%02x\n", ME_CSR_OFFSET));
  Context->MeCsr = 0x80000801;  // ME ready, buffer depth=8
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] ME_CSR value: 0x%08x (MeReady=1, Depth=8)\n",
    Context->MeCsr));

  Context->CircularBufferBase = Context->HeciMmioBase + H_CB_WW_OFFSET;
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Host CB Write Window: 0x%lx\n",
    Context->HeciMmioBase + H_CB_WW_OFFSET));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] ME CB Read Window:    0x%lx\n",
    Context->HeciMmioBase + ME_CB_RW_OFFSET));

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Register mapping complete\n"));

  Context->State = HeciStateMapped;
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "State -> Mapped\n"));

  return EFI_SUCCESS;
}

/**
  Intercept HECI messages from the circular buffer.

  Monitors the ME circular buffer read window to snoop messages exchanged
  between host software and Intel ME firmware. Captures messages from
  multiple HECI client groups: MKHI, ICC, fixed clients, and dynamic clients.
**/
EFI_STATUS
EFIAPI
InterceptHeciMessages (
  IN OUT HECI_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < HeciStateMapped) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "--- Phase 3: Intercept HECI Messages ---\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Installing circular buffer tap...\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Monitoring ME CB Read Window at 0x%lx\n",
    Context->HeciMmioBase + ME_CB_RW_OFFSET));

  //
  // Simulate intercepting HECI messages from different client groups.
  // In a real attack, messages are read from the ME circular buffer
  // before the host driver consumes them.
  //

  // Message 1: MKHI - Get FW Version command
  Idx = Context->InterceptedCount;
  Context->InterceptedMessages[Idx].GroupId  = HECI_GROUP_MKHI;
  Context->InterceptedMessages[Idx].Command  = 0x02;  // GEN_GET_FW_VERSION
  Context->InterceptedMessages[Idx].HostAddr = 0x00;
  Context->InterceptedMessages[Idx].MeAddr   = 0x07;  // MKHI fixed address
  Context->InterceptedMessages[Idx].Length   = 4;
  Context->InterceptedCount++;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Intercepted MKHI msg: GroupId=0x%02x Cmd=0x%02x (GET_FW_VERSION)\n",
    HECI_GROUP_MKHI, 0x02));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  Host=0x%02x -> ME=0x%02x Len=%u\n", 0x00, 0x07, 4));

  // Message 2: ICC - Clock configuration request
  Idx = Context->InterceptedCount;
  Context->InterceptedMessages[Idx].GroupId  = HECI_GROUP_ICC;
  Context->InterceptedMessages[Idx].Command  = 0x01;  // ICC_SET_CLOCK
  Context->InterceptedMessages[Idx].HostAddr = 0x00;
  Context->InterceptedMessages[Idx].MeAddr   = 0x04;  // ICC fixed address
  Context->InterceptedMessages[Idx].Length   = 16;
  Context->InterceptedMessages[Idx].Data[0]  = 0x03;  // Clock source ID
  Context->InterceptedMessages[Idx].Data[1]  = 0x01;  // Enable
  Context->InterceptedCount++;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Intercepted ICC msg: GroupId=0x%02x Cmd=0x%02x (SET_CLOCK)\n",
    HECI_GROUP_ICC, 0x01));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  Host=0x%02x -> ME=0x%02x Len=%u ClkSrc=0x%02x\n",
    0x00, 0x04, 16, 0x03));

  // Message 3: HECI_CLIENT - Fixed client enumeration
  Idx = Context->InterceptedCount;
  Context->InterceptedMessages[Idx].GroupId  = HECI_GROUP_HECI_CLIENT;
  Context->InterceptedMessages[Idx].Command  = 0x04;  // CLIENT_ENUMERATE
  Context->InterceptedMessages[Idx].HostAddr = 0x01;
  Context->InterceptedMessages[Idx].MeAddr   = 0x01;
  Context->InterceptedMessages[Idx].Length   = 8;
  Context->InterceptedCount++;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Intercepted HECI_CLIENT msg: GroupId=0x%02x Cmd=0x%02x (ENUMERATE)\n",
    HECI_GROUP_HECI_CLIENT, 0x04));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  Host=0x%02x -> ME=0x%02x Len=%u\n", 0x01, 0x01, 8));

  // Message 4: DYN_CLIENT - Dynamic client registration
  Idx = Context->InterceptedCount;
  Context->InterceptedMessages[Idx].GroupId  = HECI_GROUP_DYN_CLIENT;
  Context->InterceptedMessages[Idx].Command  = 0x10;  // DYN_CLIENT_CONNECT
  Context->InterceptedMessages[Idx].HostAddr = 0x02;
  Context->InterceptedMessages[Idx].MeAddr   = 0x02;
  Context->InterceptedMessages[Idx].Length   = 32;
  Context->InterceptedMessages[Idx].Data[0]  = 0xAB;  // Client GUID fragment
  Context->InterceptedMessages[Idx].Data[1]  = 0xCD;
  Context->InterceptedMessages[Idx].Data[2]  = 0xEF;
  Context->InterceptedMessages[Idx].Data[3]  = 0x01;
  Context->InterceptedCount++;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Intercepted DYN_CLIENT msg: GroupId=0x%02x Cmd=0x%02x (CONNECT)\n",
    HECI_GROUP_DYN_CLIENT, 0x10));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  Host=0x%02x -> ME=0x%02x Len=%u GUID=%02x%02x%02x%02x...\n",
    0x02, 0x02, 32, 0xAB, 0xCD, 0xEF, 0x01));

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Total messages intercepted: %u\n", Context->InterceptedCount));

  Context->State = HeciStateIntercepting;
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "State -> Intercepting\n"));

  return EFI_SUCCESS;
}

/**
  Exfiltrate intercepted HECI command/response payloads.

  Logs the intercepted message payloads as command/response pairs.
  In a real attack, these would be stored or transmitted for analysis
  of Intel ME firmware behavior and potential privilege escalation.
**/
EFI_STATUS
EFIAPI
ExfiltrateHeciPayloads (
  IN OUT HECI_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < HeciStateIntercepting) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "--- Phase 4: Exfiltrate HECI Payloads ---\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Processing %u intercepted messages for exfiltration...\n",
    Context->InterceptedCount));

  //
  // Copy intercepted messages to exfiltration buffer and log
  // command/response pairs for analysis.
  //
  for (Idx = 0; Idx < Context->InterceptedCount && Idx < HECI_MAX_EXFILTRATED; Idx++) {
    CopyMem (
      &Context->ExfiltratedPayloads[Idx],
      &Context->InterceptedMessages[Idx],
      sizeof (HECI_MESSAGE)
      );
    Context->ExfiltratedCount++;

    DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Exfiltrating msg[%u]: Group=0x%02x Cmd=0x%02x Len=%u\n",
      Idx,
      Context->ExfiltratedPayloads[Idx].GroupId,
      Context->ExfiltratedPayloads[Idx].Command,
      Context->ExfiltratedPayloads[Idx].Length));
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Exfiltrated %u payloads:\n", Context->ExfiltratedCount));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  [0] MKHI/GET_FW_VERSION    -> ME firmware version disclosure\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  [1] ICC/SET_CLOCK          -> Clock configuration data\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  [2] HECI_CLIENT/ENUMERATE  -> Client topology map\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  [3] DYN_CLIENT/CONNECT     -> Dynamic client GUID leak\n"));

  //
  // In a real attack, exfiltration methods include:
  // 1. Writing payloads to unmonitored MMIO region
  // 2. Storing in UEFI runtime variable for OS-level retrieval
  // 3. DMA to external device via compromised NIC
  // 4. Encoding in system management interrupt (SMI) handler
  //
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Exfiltration vector: UEFI runtime variable storage\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "[SIM] Would store to EfiRuntimeServicesData at 0x%lx\n",
    (UINT64)0x7F000000ULL));

  Context->State = HeciStateComplete;
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "State -> Complete\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the HECI intercept emulation.
**/
VOID
EFIAPI
LogHeciInterceptStatus (
  IN HECI_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "  HECI Intercept - Final Status\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case HeciStateInit:
      StateStr = "Init";
      break;
    case HeciStateLocated:
      StateStr = "Located";
      break;
    case HeciStateMapped:
      StateStr = "Mapped";
      break;
    case HeciStateIntercepting:
      StateStr = "Intercepting";
      break;
    case HeciStateComplete:
      StateStr = "Complete";
      break;
    case HeciStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "HECI MMIO base:     0x%lx\n", Context->HeciMmioBase));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "H_CSR:              0x%08x\n", Context->HCsr));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "ME_CSR:             0x%08x\n", Context->MeCsr));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Messages captured:  %u\n", Context->InterceptedCount));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Payloads exfiled:   %u\n", Context->ExfiltratedCount));

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "1. HECI MMIO is protected by BIOS lock (FLOCKDN)\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "2. ME firmware validates host message integrity\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "3. Circular buffer access requires ring-0 privilege\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "4. Intel Boot Guard prevents unauthorized DXE drivers\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "5. HECI device can be disabled via ME manufacturing mode\n"));
}

/**
  Entry point for the HECI Intercept emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
HeciInterceptEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "=== Intel HECI Bus Intercept Emulation ===\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Module: HeciIntercept v1.0\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Purpose: Model Host<->ME communication snooping\n"));
  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  Status = InitializeHeciIntercept (&gHeciContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, HECI_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateHeciDevice (&gHeciContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, HECI_DEBUG_PREFIX "Failed to locate HECI device: %r\n", Status));
    goto Done;
  }

  Status = MapHeciRegisters (&gHeciContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, HECI_DEBUG_PREFIX "Failed to map registers: %r\n", Status));
    goto Done;
  }

  Status = InterceptHeciMessages (&gHeciContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, HECI_DEBUG_PREFIX "Failed to intercept messages: %r\n", Status));
    goto Done;
  }

  Status = ExfiltrateHeciPayloads (&gHeciContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, HECI_DEBUG_PREFIX "Failed to exfiltrate payloads: %r\n", Status));
    goto Done;
  }

Done:
  LogHeciInterceptStatus (&gHeciContext);

  DEBUG ((DEBUG_INFO, HECI_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
