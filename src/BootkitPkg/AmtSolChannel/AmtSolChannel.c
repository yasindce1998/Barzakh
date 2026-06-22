/** @file
  AMT Serial-over-LAN Channel Emulation - Implementation

  Emulates covert Command & Control (C2) communication over Intel Active
  Management Technology (AMT) Serial-over-LAN (SOL). Models PCI device
  enumeration, AMT provisioning verification, bidirectional C2 command
  exchange, and data exfiltration over the out-of-band SOL channel.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  This module serves as a research reference for defensive security teams
  studying Intel AMT abuse as a covert channel (Platinum APT technique).

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "AmtSolChannel.h"

STATIC AMT_SOL_CONTEXT  gAmtSolContext;

/**
  Initialize AMT SOL channel context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeAmtSolChannel (
  OUT AMT_SOL_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (AMT_SOL_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = AmtStateInit;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Target: Intel AMT Serial-over-LAN covert C2 channel\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Attack vector: Out-of-band SOL communication (Platinum APT)\n"));

  return EFI_SUCCESS;
}

/**
  Locate the Intel AMT SOL device via PCI enumeration.

  The AMT SOL controller is exposed as PCI B0:D22:F3 on Intel platforms
  with vPro/AMT capability. The SOL function shares the MEI (Management
  Engine Interface) PCI device but operates on a separate function number.
**/
EFI_STATUS
EFIAPI
LocateAmtDevice (
  IN OUT AMT_SOL_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "--- Phase 1: Locate AMT SOL Device ---\n"));

  //
  // In a real attack, the AMT SOL device is located via:
  // 1. PCI configuration space enumeration (Bus 0, Dev 22, Fun 3)
  // 2. Vendor/Device ID check (8086h / specific SKU)
  // 3. BAR0 read for MMIO base address
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Scanning PCI bus for AMT SOL controller...\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Checking B%d:D%d:F%d (Intel MEI SOL function)\n",
    AMT_SOL_PCI_BUS, AMT_SOL_PCI_DEV, AMT_SOL_PCI_FUN));

  //
  // Simulate reading PCI configuration space
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] PCI Config Read: VendorId=0x8086, DeviceId=0xA13D\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] PCI Config Read: Class=07h/00h (Serial/UART)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] PCI Config Read: BAR0=0xDF22C000 (MMIO)\n"));

  Context->SolMmioBase = 0xDF22C000ULL;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "SOL MMIO base address: 0x%lx\n", Context->SolMmioBase));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "SOL MMIO region size:  0x%x bytes\n", SOL_MMIO_SIZE));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  Receive control: 0x%lx\n", Context->SolMmioBase + SOL_RECV_CTRL));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  Send control:    0x%lx\n", Context->SolMmioBase + SOL_SEND_CTRL));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  Status register: 0x%lx\n", Context->SolMmioBase + SOL_STATUS_REG));

  Context->State = AmtStateLocated;
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "State -> Located\n"));

  return EFI_SUCCESS;
}

/**
  Initialize the SOL channel by verifying AMT provisioning state.

  AMT must be fully provisioned (state == PROVISION_COMPLETE) for the SOL
  channel to be usable. Once confirmed, the SOL IDER registers are
  configured for bidirectional serial communication that bypasses the OS.
**/
EFI_STATUS
EFIAPI
InitializeSolChannel (
  IN OUT AMT_SOL_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < AmtStateLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "--- Phase 2: Initialize SOL Channel ---\n"));

  //
  // Check AMT provisioning state. SOL requires AMT to be fully
  // provisioned (enterprise mode with remote configuration complete).
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Reading AMT provisioning state at offset 0x%x\n",
    AMT_PROVISIONING_STATE));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] MMIO Read 0x%lx => 0x%08x\n",
    Context->SolMmioBase + AMT_PROVISIONING_STATE, AMT_PROVISION_COMPLETE));

  Context->ProvisioningState = AMT_PROVISION_COMPLETE;

  if (Context->ProvisioningState != AMT_PROVISION_COMPLETE) {
    DEBUG ((DEBUG_ERROR, AMT_DEBUG_PREFIX "AMT not provisioned (state=0x%x), SOL unavailable\n",
      Context->ProvisioningState));
    Context->State = AmtStateError;
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "AMT provisioning state: COMPLETE (0x%02x)\n",
    Context->ProvisioningState));

  //
  // Configure SOL IDER (IDE Redirection) registers for serial channel
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Configuring SOL channel registers:\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] MMIO Write 0x%lx <= 0x01 (enable receive)\n",
    Context->SolMmioBase + SOL_RECV_CTRL));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] MMIO Write 0x%lx <= 0x01 (enable send)\n",
    Context->SolMmioBase + SOL_SEND_CTRL));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Reading SOL status: channel active, no errors\n"));

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "SOL channel initialized successfully\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  Channel operates out-of-band (invisible to host OS)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  Traffic routed via Intel ME firmware network stack\n"));

  Context->State = AmtStateProvisioned;
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "State -> Provisioned\n"));

  return EFI_SUCCESS;
}

/**
  Establish bidirectional C2 channel over SOL.

  Simulates receiving commands from a remote C2 server and sending
  responses back. The SOL channel provides a covert, OS-invisible
  communication path because it operates through the Intel ME firmware
  network stack, independent of the host CPU and OS.
**/
EFI_STATUS
EFIAPI
EstablishC2Channel (
  IN OUT AMT_SOL_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < AmtStateProvisioned) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "--- Phase 3: Establish C2 Channel ---\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Opening bidirectional covert channel over AMT SOL...\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "C2 server: communicates via ME firmware network stack\n"));

  //
  // Simulate receiving C2 commands over the SOL channel.
  // In a real attack (Platinum APT), the ME firmware network stack
  // provides TCP/IP connectivity independent of the host OS, allowing
  // attackers to communicate even when the OS is powered off (S3/S5).
  //

  // Command 1: Beacon (heartbeat/check-in)
  Idx = Context->ReceivedCommands.Count;
  Context->ReceivedCommands.Commands[Idx].CommandId   = 0x01;
  Context->ReceivedCommands.Commands[Idx].PayloadSize = 8;
  Context->ReceivedCommands.Commands[Idx].Payload[0]  = 'B';
  Context->ReceivedCommands.Commands[Idx].Payload[1]  = 'E';
  Context->ReceivedCommands.Commands[Idx].Payload[2]  = 'A';
  Context->ReceivedCommands.Commands[Idx].Payload[3]  = 'C';
  Context->ReceivedCommands.Commands[Idx].Payload[4]  = 'O';
  Context->ReceivedCommands.Commands[Idx].Payload[5]  = 'N';
  Context->ReceivedCommands.Commands[Idx].Payload[6]  = 0x00;
  Context->ReceivedCommands.Commands[Idx].Payload[7]  = 0x01;
  Context->ReceivedCommands.Count++;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL RECV: Cmd=0x01 (BEACON) Size=8\n"));

  // Command 2: Execute (remote command execution request)
  Idx = Context->ReceivedCommands.Count;
  Context->ReceivedCommands.Commands[Idx].CommandId   = 0x02;
  Context->ReceivedCommands.Commands[Idx].PayloadSize = 16;
  Context->ReceivedCommands.Commands[Idx].Payload[0]  = 'E';
  Context->ReceivedCommands.Commands[Idx].Payload[1]  = 'X';
  Context->ReceivedCommands.Commands[Idx].Payload[2]  = 'E';
  Context->ReceivedCommands.Commands[Idx].Payload[3]  = 'C';
  Context->ReceivedCommands.Commands[Idx].Payload[4]  = ':';
  Context->ReceivedCommands.Commands[Idx].Payload[5]  = 'e';
  Context->ReceivedCommands.Commands[Idx].Payload[6]  = 'n';
  Context->ReceivedCommands.Commands[Idx].Payload[7]  = 'u';
  Context->ReceivedCommands.Commands[Idx].Payload[8]  = 'm';
  Context->ReceivedCommands.Count++;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL RECV: Cmd=0x02 (EXEC) Size=16 payload='EXEC:enum'\n"));

  // Command 3: Exfiltrate (data exfiltration request)
  Idx = Context->ReceivedCommands.Count;
  Context->ReceivedCommands.Commands[Idx].CommandId   = 0x03;
  Context->ReceivedCommands.Commands[Idx].PayloadSize = 12;
  Context->ReceivedCommands.Commands[Idx].Payload[0]  = 'E';
  Context->ReceivedCommands.Commands[Idx].Payload[1]  = 'X';
  Context->ReceivedCommands.Commands[Idx].Payload[2]  = 'F';
  Context->ReceivedCommands.Commands[Idx].Payload[3]  = 'I';
  Context->ReceivedCommands.Commands[Idx].Payload[4]  = 'L';
  Context->ReceivedCommands.Commands[Idx].Payload[5]  = ':';
  Context->ReceivedCommands.Commands[Idx].Payload[6]  = 'c';
  Context->ReceivedCommands.Commands[Idx].Payload[7]  = 'r';
  Context->ReceivedCommands.Commands[Idx].Payload[8]  = 'e';
  Context->ReceivedCommands.Commands[Idx].Payload[9]  = 'd';
  Context->ReceivedCommands.Commands[Idx].Payload[10] = 's';
  Context->ReceivedCommands.Count++;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL RECV: Cmd=0x03 (EXFIL) Size=12 payload='EXFIL:creds'\n"));

  //
  // Simulate sending responses back to C2 server
  //

  // Response 1: Beacon ACK
  Idx = Context->SentResponses.Count;
  Context->SentResponses.Commands[Idx].CommandId   = 0x81;
  Context->SentResponses.Commands[Idx].PayloadSize = 4;
  Context->SentResponses.Commands[Idx].Payload[0]  = 'A';
  Context->SentResponses.Commands[Idx].Payload[1]  = 'C';
  Context->SentResponses.Commands[Idx].Payload[2]  = 'K';
  Context->SentResponses.Commands[Idx].Payload[3]  = 0x00;
  Context->SentResponses.Count++;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL SEND: Resp=0x81 (BEACON_ACK) Size=4\n"));

  // Response 2: Exec result
  Idx = Context->SentResponses.Count;
  Context->SentResponses.Commands[Idx].CommandId   = 0x82;
  Context->SentResponses.Commands[Idx].PayloadSize = 32;
  Context->SentResponses.Commands[Idx].Payload[0]  = 0x00;  // Status: success
  Context->SentResponses.Count++;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL SEND: Resp=0x82 (EXEC_RESULT) Size=32 status=OK\n"));

  // Response 3: Exfil ACK
  Idx = Context->SentResponses.Count;
  Context->SentResponses.Commands[Idx].CommandId   = 0x83;
  Context->SentResponses.Commands[Idx].PayloadSize = 4;
  Context->SentResponses.Commands[Idx].Payload[0]  = 'O';
  Context->SentResponses.Commands[Idx].Payload[1]  = 'K';
  Context->SentResponses.Count++;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL SEND: Resp=0x83 (EXFIL_ACK) Size=4\n"));

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "C2 channel established: %u commands received, %u responses sent\n",
    Context->ReceivedCommands.Count, Context->SentResponses.Count));

  Context->State = AmtStateC2Active;
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "State -> C2Active\n"));

  return EFI_SUCCESS;
}

/**
  Simulate data exfiltration over the SOL channel.

  Models the exfiltration of sensitive data (credentials, system info)
  through the covert SOL channel. Because AMT SOL operates at the firmware
  level via the ME network stack, this traffic is invisible to host-based
  firewalls, EDR, and network monitoring tools on the host.
**/
EFI_STATUS
EFIAPI
ExfiltrateOverSol (
  IN OUT AMT_SOL_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < AmtStateC2Active) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "--- Phase 4: Exfiltrate Data Over SOL ---\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Exfiltrating sensitive data via covert SOL channel...\n"));

  //
  // Simulate credential exfiltration
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Collecting cached credentials from memory...\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Found: domain\\admin (NTLM hash, 64 bytes)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Found: service_account (Kerberos TGT, 1024 bytes)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL SEND: credential blob (1088 bytes)\n"));
  Context->BytesExfiltrated += 1088;

  //
  // Simulate system information exfiltration
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Collecting system enumeration data...\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Hostname, domain, IP config, installed software\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL SEND: system info blob (2048 bytes)\n"));
  Context->BytesExfiltrated += 2048;

  //
  // Simulate security product enumeration
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] Enumerating security products...\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] AV/EDR status, firewall rules, logging config\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "[SIM] SOL SEND: security product info (512 bytes)\n"));
  Context->BytesExfiltrated += 512;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Total bytes exfiltrated: %u\n", Context->BytesExfiltrated));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  All traffic routed via ME firmware (OS-invisible)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  No host network stack involvement\n"));

  Context->State = AmtStateComplete;
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "State -> Complete\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the AMT SOL channel emulation.
**/
VOID
EFIAPI
LogAmtSolStatus (
  IN AMT_SOL_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "  AMT SOL Channel - Final Status\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case AmtStateInit:
      StateStr = "Init";
      break;
    case AmtStateLocated:
      StateStr = "Located";
      break;
    case AmtStateProvisioned:
      StateStr = "Provisioned";
      break;
    case AmtStateC2Active:
      StateStr = "C2Active";
      break;
    case AmtStateComplete:
      StateStr = "Complete";
      break;
    case AmtStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "SOL MMIO base:      0x%lx\n", Context->SolMmioBase));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "AMT provisioned:    %a\n",
    Context->ProvisioningState == AMT_PROVISION_COMPLETE ? "YES" : "NO"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Commands received:  %u\n", Context->ReceivedCommands.Count));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Responses sent:     %u\n", Context->SentResponses.Count));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Bytes exfiltrated:  %u\n", Context->BytesExfiltrated));

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "1. Disable AMT/SOL in BIOS if not required by enterprise policy\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "2. Monitor ME firmware version for known vulnerabilities\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "3. Network segmentation: isolate AMT management traffic (port 16992-16995)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "4. Use AMT provisioning audit logs to detect unauthorized config\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "5. Deploy out-of-band network monitoring at switch/tap level\n"));
}

/**
  Entry point for the AMT SOL Channel emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
AmtSolChannelEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "=== Intel AMT SOL Covert C2 Channel Emulation ===\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Module: AmtSolChannel v1.0\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Purpose: Model covert C2 over AMT Serial-over-LAN (Platinum APT)\n"));
  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  Status = InitializeAmtSolChannel (&gAmtSolContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, AMT_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateAmtDevice (&gAmtSolContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, AMT_DEBUG_PREFIX "Failed to locate AMT device: %r\n", Status));
    goto Done;
  }

  Status = InitializeSolChannel (&gAmtSolContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, AMT_DEBUG_PREFIX "Failed to initialize SOL channel: %r\n", Status));
    goto Done;
  }

  Status = EstablishC2Channel (&gAmtSolContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, AMT_DEBUG_PREFIX "Failed to establish C2 channel: %r\n", Status));
    goto Done;
  }

  Status = ExfiltrateOverSol (&gAmtSolContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, AMT_DEBUG_PREFIX "Failed to exfiltrate data: %r\n", Status));
    goto Done;
  }

Done:
  LogAmtSolStatus (&gAmtSolContext);

  DEBUG ((DEBUG_INFO, AMT_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
