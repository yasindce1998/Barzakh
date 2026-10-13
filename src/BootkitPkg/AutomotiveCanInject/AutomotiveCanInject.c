/** @file
  Automotive CAN Injection Backdoor Emulation - Implementation

  Emulates CAN bus injection backdoors delivered through compromised ECU
  firmware (Ring 0). Models ECU node enumeration on the vehicle bus, a
  virtual CAN-over-UEFI protocol that carries frames through a local ring
  buffer, and frame injection with arbitration-ID spoofing. In a real
  attack, a firmware implant inside an ECU uses this technique to emit
  frames that receiving ECUs trust because the arbitration ID matches a
  genuine node (the technique behind the Jeep Cherokee research and later
  OEM-specific attacks).

  SIMULATION ONLY - All hardware operations are logged, never executed.
  No CAN controller, transceiver, or ECU is accessed; frames circulate
  only inside this module's own buffers.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "AutomotiveCanInject.h"

STATIC CAN_INJECT_CONTEXT  gCanInjectContext;

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
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "GetTime failed: %r - aborting\n", Status));
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
    DEBUG ((DEBUG_WARN, CAN_DEBUG_PREFIX "Expiry date reached - aborting\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Virtual protocol member: transmit one CAN frame.

  In SIMULATION mode the frame is copied into the local ring buffer and
  logged; no CAN controller register is ever touched.
**/
STATIC
EFI_STATUS
EFIAPI
CanProtocolTransmitFrame (
  IN BARZAKH_CAN_PROTOCOL  *This,
  IN CAN_FRAME             *Frame
  )
{
  CAN_INJECT_CONTEXT  *Context;

  if ((This == NULL) || (Frame == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Context = BASE_CR (This, CAN_INJECT_CONTEXT, CanProtocol);

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "[SIM] CAN TX: ID=0x%03x (%a, %a) DLC=%u data="
    "%02x %02x %02x %02x %02x %02x %02x %02x\n",
    Frame->ArbitrationId,
    Frame->ExtendedId ? "ext29" : "std11",
    Frame->Spoofed ? "SPOOFED" : "genuine",
    Frame->Dlc,
    Frame->Data[0], Frame->Data[1], Frame->Data[2], Frame->Data[3],
    Frame->Data[4], Frame->Data[5], Frame->Data[6], Frame->Data[7]));

  if (Context->InjectedCount >= CAN_MAX_INJECTED_FRAMES) {
    Context->Stats.FramesDropped++;
    DEBUG ((DEBUG_WARN, CAN_DEBUG_PREFIX "[SIM] CAN TX ring full - frame dropped\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (&Context->InjectedFrames[Context->InjectedTail], Frame, sizeof (CAN_FRAME));
  Context->InjectedTail = (Context->InjectedTail + 1) % CAN_MAX_INJECTED_FRAMES;
  Context->InjectedCount++;
  Context->Stats.FramesTransmitted++;

  return EFI_SUCCESS;
}

/**
  Virtual protocol member: receive one CAN frame.

  Pops the oldest frame from the local ring buffer (simulation only).
**/
STATIC
EFI_STATUS
EFIAPI
CanProtocolReceiveFrame (
  IN BARZAKH_CAN_PROTOCOL  *This,
  OUT CAN_FRAME            *Frame
  )
{
  CAN_INJECT_CONTEXT  *Context;

  if ((This == NULL) || (Frame == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Context = BASE_CR (This, CAN_INJECT_CONTEXT, CanProtocol);

  if (Context->InjectedCount == 0) {
    return EFI_NOT_READY;
  }

  CopyMem (Frame, &Context->InjectedFrames[Context->InjectedHead], sizeof (CAN_FRAME));
  Context->InjectedHead = (Context->InjectedHead + 1) % CAN_MAX_INJECTED_FRAMES;
  Context->InjectedCount--;
  Context->Stats.FramesReceived++;

  return EFI_SUCCESS;
}

/**
  Virtual protocol member: read emulated bus statistics.
**/
STATIC
EFI_STATUS
EFIAPI
CanProtocolGetStats (
  IN BARZAKH_CAN_PROTOCOL  *This,
  OUT CAN_STATS            *Stats
  )
{
  CAN_INJECT_CONTEXT  *Context;

  if ((This == NULL) || (Stats == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Context = BASE_CR (This, CAN_INJECT_CONTEXT, CanProtocol);
  CopyMem (Stats, &Context->Stats, sizeof (CAN_STATS));

  return EFI_SUCCESS;
}

/**
  Initialize CAN injection context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeCanInject (
  OUT CAN_INJECT_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (CAN_INJECT_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = CanStateInit;

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Target: ECU-firmware CAN injection backdoor (Ring 0)\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Attack vector: arbitration-ID spoofing on vehicle bus\n"));

  return EFI_SUCCESS;
}

/**
  Enumerate the simulated in-vehicle CAN bus.

  Models the discovery phase of an ECU implant: passive bus sniffing to
  inventory node arbitration IDs before injection begins. In a real
  attack the implant records traffic to learn which IDs each ECU owns.
**/
EFI_STATUS
EFIAPI
EnumerateCanBus (
  IN OUT CAN_INJECT_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "--- Phase 1: Enumerate CAN Bus ---\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "[SIM] Bus: classic CAN 2.0B, %u kbit/s\n", CAN_BITRATE_KBPS));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "[SIM] Passive sniff of bus traffic for inventory window...\n"));

  //
  // In a real attack, ECU identities are learned by observing periodic
  // frames and matching arbitration IDs to OEM DBC database entries.
  //
  Context->Ecus[0].Name          = "Gateway (central GWM)";
  Context->Ecus[0].ArbitrationId = CAN_ID_GATEWAY_ECU;
  Context->Ecus[0].ExtendedId    = FALSE;
  Context->Ecus[0].SpoofTarget   = FALSE;

  Context->Ecus[1].Name          = "Engine control (ECM)";
  Context->Ecus[1].ArbitrationId = CAN_ID_ENGINE_ECU;
  Context->Ecus[1].ExtendedId    = FALSE;
  Context->Ecus[1].SpoofTarget   = TRUE;

  Context->Ecus[2].Name          = "Brake control (ABS)";
  Context->Ecus[2].ArbitrationId = CAN_ID_ABS_ECU;
  Context->Ecus[2].ExtendedId    = FALSE;
  Context->Ecus[2].SpoofTarget   = TRUE;

  Context->Ecus[3].Name          = "Body control (BCM)";
  Context->Ecus[3].ArbitrationId = CAN_ID_BODY_ECU;
  Context->Ecus[3].ExtendedId    = FALSE;
  Context->Ecus[3].SpoofTarget   = TRUE;

  Context->Ecus[4].Name          = "Instrument cluster (IC)";
  Context->Ecus[4].ArbitrationId = CAN_ID_INSTRUMENT_ECU;
  Context->Ecus[4].ExtendedId    = FALSE;
  Context->Ecus[4].SpoofTarget   = FALSE;

  Context->EcuCount = 5;

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Discovered %u ECU nodes:\n", Context->EcuCount));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  0x%03x  %a\n",
    Context->Ecus[0].ArbitrationId, Context->Ecus[0].Name));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  0x%03x  %a [SPOOF TARGET]\n",
    Context->Ecus[1].ArbitrationId, Context->Ecus[1].Name));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  0x%03x  %a [SPOOF TARGET]\n",
    Context->Ecus[2].ArbitrationId, Context->Ecus[2].Name));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  0x%03x  %a [SPOOF TARGET]\n",
    Context->Ecus[3].ArbitrationId, Context->Ecus[3].Name));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  0x%03x  %a\n",
    Context->Ecus[4].ArbitrationId, Context->Ecus[4].Name));

  Context->State = CanStateBusEnumerated;
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "State -> BusEnumerated\n"));

  return EFI_SUCCESS;
}

/**
  Install the virtual CAN-over-UEFI protocol.

  The protocol is the implant's local I/O abstraction: instead of writing
  CAN controller registers, all frames flow through this protocol into a
  ring buffer owned by the module. In SIMULATION mode nothing outside the
  module's own memory is involved in any way.
**/
EFI_STATUS
EFIAPI
InstallCanProtocol (
  IN OUT CAN_INJECT_CONTEXT  *Context
  )
{
  EFI_STATUS      Status;
  STATIC EFI_GUID  CanProtocolGuid = BARZAKH_CAN_PROTOCOL_GUID;

  if (Context == NULL || Context->State < CanStateBusEnumerated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "--- Phase 2: Install Virtual CAN Protocol ---\n"));

  Context->CanProtocol.TransmitFrame = CanProtocolTransmitFrame;
  Context->CanProtocol.ReceiveFrame  = CanProtocolReceiveFrame;
  Context->CanProtocol.GetStats      = CanProtocolGetStats;

  Context->ProtocolHandle = NULL;
  Status = gBS->InstallProtocolInterface (
                  &Context->ProtocolHandle,
                  &CanProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &Context->CanProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "InstallProtocolInterface failed: %r\n", Status));
    Context->State = CanStateError;
    return Status;
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Virtual CAN-over-UEFI protocol installed (handle=0x%p)\n",
    Context->ProtocolHandle));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  Members: TransmitFrame / ReceiveFrame / GetStats\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "[SIM] In a functional build the protocol would bind to the\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "[SIM] ECU's CAN controller mailboxes instead of this buffer\n"));

  Context->State = CanStateProtocolInstalled;
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "State -> ProtocolInstalled\n"));

  return EFI_SUCCESS;
}

/**
  Emulate frame injection with arbitration-ID spoofing.

  Models the core backdoor behavior: the implant transmits frames that
  carry the arbitration IDs of genuine ECUs (engine, brake, body) so that
  receiving nodes accept attacker-controlled payloads. All frames are
  routed through the virtual protocol into the local ring buffer.
**/
EFI_STATUS
EFIAPI
InjectCanFrames (
  IN OUT CAN_INJECT_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;
  CAN_FRAME   Frame;
  UINT32      Loop;

  if (Context == NULL || Context->State < CanStateProtocolInstalled) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "--- Phase 3: Inject Spoofed CAN Frames ---\n"));

  //
  // Frame 1: spoof the engine ECU arbitration ID with a crafted
  // throttle-position payload (replay/forgery of powertrain traffic).
  //
  Frame.ArbitrationId = CAN_ID_ENGINE_ECU;
  Frame.ExtendedId    = FALSE;
  Frame.Spoofed       = TRUE;
  Frame.Dlc           = 8;
  Frame.Data[0]       = 0x00;                    // Counter
  Frame.Data[1]       = 0x74;                    // Throttle position (crafted)
  Frame.Data[2]       = 0x40;
  Frame.Data[3]       = 0x00;
  Frame.Data[4]       = 0x8C;                    // Engine RPM (crafted)
  Frame.Data[5]       = 0xA0;
  Frame.Data[6]       = 0x7D;
  Frame.Data[7]       = 0x00;

  Status = Context->CanProtocol.TransmitFrame (&Context->CanProtocol, &Frame);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Frame 1 injection failed: %r\n", Status));
  }

  //
  // Frame 2: spoof the ABS ECU arbitration ID with wheel-speed data
  // (models brake-system trust abuse).
  //
  Frame.ArbitrationId = CAN_ID_ABS_ECU;
  Frame.ExtendedId    = FALSE;
  Frame.Spoofed       = TRUE;
  Frame.Dlc           = 8;
  Frame.Data[0]       = 0x00;
  Frame.Data[1]       = 0x00;
  Frame.Data[2]       = 0x3E;                    // Wheel speed FL (crafted)
  Frame.Data[3]       = 0x80;
  Frame.Data[4]       = 0x3E;                    // Wheel speed FR (crafted)
  Frame.Data[5]       = 0x80;
  Frame.Data[6]       = 0x00;
  Frame.Data[7]       = 0x00;

  Status = Context->CanProtocol.TransmitFrame (&Context->CanProtocol, &Frame);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Frame 2 injection failed: %r\n", Status));
  }

  //
  // Frame 3: spoof the body control ECU arbitration ID (unlock command
  // replay model).
  //
  Frame.ArbitrationId = CAN_ID_BODY_ECU;
  Frame.ExtendedId    = FALSE;
  Frame.Spoofed       = TRUE;
  Frame.Dlc           = 4;
  Frame.Data[0]       = 0x01;                    // Door control opcode
  Frame.Data[1]       = 0xFF;                    // All doors unlock
  Frame.Data[2]       = 0x00;
  Frame.Data[3]       = 0x00;
  Frame.Data[4]       = 0x00;
  Frame.Data[5]       = 0x00;
  Frame.Data[6]       = 0x00;
  Frame.Data[7]       = 0x00;

  Status = Context->CanProtocol.TransmitFrame (&Context->CanProtocol, &Frame);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Frame 3 injection failed: %r\n", Status));
  }

  //
  // Frame 4: extended 29-bit telemetry ID (models implant C2 beacons
  // hidden on the diagnostic/telemetry address range).
  //
  Frame.ArbitrationId = CAN_ID_EXTENDED_TELEMETRY;
  Frame.ExtendedId    = TRUE;
  Frame.Spoofed       = TRUE;
  Frame.Dlc           = 8;
  Frame.Data[0]       = 'B';
  Frame.Data[1]       = 'E';
  Frame.Data[2]       = 'A';
  Frame.Data[3]       = 'C';
  Frame.Data[4]       = 'O';
  Frame.Data[5]       = 'N';
  Frame.Data[6]       = 0x00;
  Frame.Data[7]       = 0x01;

  Status = Context->CanProtocol.TransmitFrame (&Context->CanProtocol, &Frame);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Frame 4 injection failed: %r\n", Status));
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Injected %u spoofed frames via virtual protocol\n", 4));

  //
  // Demonstrate the receive path: the implant reads back two frames
  // from its own ring buffer (models response collection).
  //
  for (Loop = 0; Loop < 2; Loop++) {
    Status = Context->CanProtocol.ReceiveFrame (&Context->CanProtocol, &Frame);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Readback %u failed: %r\n", Loop, Status));
    } else {
      DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "[SIM] CAN RX readback: ID=0x%03x DLC=%u\n",
        Frame.ArbitrationId, Frame.Dlc));
    }
  }

  Context->State = CanStateFramesInjected;
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "State -> FramesInjected\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the CAN injection backdoor emulation.
**/
VOID
EFIAPI
LogCanInjectStatus (
  IN CAN_INJECT_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "  CAN Injection Backdoor - Final Status\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case CanStateInit:
      StateStr = "Init";
      break;
    case CanStateBusEnumerated:
      StateStr = "BusEnumerated";
      break;
    case CanStateProtocolInstalled:
      StateStr = "ProtocolInstalled";
      break;
    case CanStateFramesInjected:
      StateStr = "FramesInjected";
      break;
    case CanStateComplete:
      StateStr = "Complete";
      break;
    case CanStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "ECU nodes found:    %u\n", Context->EcuCount));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Protocol handle:    0x%p\n", Context->ProtocolHandle));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Frames transmitted: %u\n", Context->Stats.FramesTransmitted));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Frames received:    %u\n", Context->Stats.FramesReceived));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Frames dropped:     %u\n", Context->Stats.FramesDropped));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Ring occupancy:     %u / %u\n",
    Context->InjectedCount, (UINT32)CAN_MAX_INJECTED_FRAMES));

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "1. Deploy CAN intrusion detection (arbitration-ID owner maps)\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "2. Verify ECU firmware images against signed OEM builds\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "3. Enable MACsec/CAN-FD authentication where the bus supports it\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "4. Gateway firewalls: filter cross-domain frames by source ID\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "5. Monitor ECU diagnostic/telemetry IDs for unexpected beacons\n"));
}

/**
  Entry point for the Automotive CAN injection emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
AutomotiveCanInjectEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "=== Automotive CAN Injection Backdoor Emulation ===\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Module: AutomotiveCanInject v1.0\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Purpose: Model ECU-firmware CAN injection (arbitration-ID spoofing)\n"));
  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  //
  // Kill-switch: refuse to run past the project expiry date.
  //
  if (!ValidateKillSwitch ()) {
    DEBUG ((DEBUG_WARN, CAN_DEBUG_PREFIX "Kill-switch triggered - aborting\n"));
    return EFI_ABORTED;
  }

  Status = InitializeCanInject (&gCanInjectContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = EnumerateCanBus (&gCanInjectContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Failed to enumerate bus: %r\n", Status));
    goto Done;
  }

  Status = InstallCanProtocol (&gCanInjectContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Failed to install protocol: %r\n", Status));
    goto Done;
  }

  Status = InjectCanFrames (&gCanInjectContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, CAN_DEBUG_PREFIX "Failed to inject frames: %r\n", Status));
    goto Done;
  }

Done:
  LogCanInjectStatus (&gCanInjectContext);

  DEBUG ((DEBUG_INFO, CAN_DEBUG_PREFIX "Module finished (research emulation complete)\n"));
  return EFI_SUCCESS;
}
