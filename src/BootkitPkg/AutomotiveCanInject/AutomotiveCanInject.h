/** @file
  Automotive CAN Injection Backdoor Emulation - Header

  Models CAN bus injection backdoors delivered through compromised ECU
  firmware (Ring 0). An implant resident in an ECU's firmware can emit
  crafted CAN frames with spoofed arbitration identifiers, causing other
  nodes on the bus to accept attacker traffic as genuine. This module
  installs a virtual CAN-over-UEFI protocol and emulates frame injection
  with arbitration-ID spoofing entirely in local memory buffers.

  All operations are SIMULATED - no CAN controller or ECU hardware is
  modified, and no frames ever leave the module's own ring buffer.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef AUTOMOTIVE_CAN_INJECT_H_
#define AUTOMOTIVE_CAN_INJECT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <BarzakhMode.h>

#define CAN_DEBUG_PREFIX  "[CAN-Emu] "

//
// Time-bomb expiry (kill-switch). Matches the project-wide default.
//
#ifndef BARZAKH_EXPIRY_DATE
#define BARZAKH_EXPIRY_DATE  "2027-05-11"
#endif

//
// Simulated CAN bus parameters (classic CAN 2.0B)
//
#define CAN_BITRATE_KBPS            500
#define CAN_STANDARD_ID_MASK        0x7FF          // 11-bit arbitration ID
#define CAN_EXTENDED_ID_MASK        0x1FFFFFFF     // 29-bit arbitration ID
#define CAN_MAX_DATA_LEN            8

//
// Simulated ECU arbitration IDs on the research vehicle bus
//
#define CAN_ID_ENGINE_ECU           0x0A1
#define CAN_ID_ABS_ECU              0x121
#define CAN_ID_GATEWAY_ECU          0x1F4
#define CAN_ID_BODY_ECU             0x2B0
#define CAN_ID_INSTRUMENT_ECU       0x3E8
#define CAN_ID_EXTENDED_TELEMETRY   0x18FF0102

//
// Table sizes
//
#define CAN_MAX_ECUS                8
#define CAN_MAX_INJECTED_FRAMES     16

//
// Virtual CAN-over-UEFI protocol GUID (Barzakh research emulation only;
// defined locally because this protocol is not part of any published spec)
//
#define BARZAKH_CAN_PROTOCOL_GUID \
  { 0x9f3b7c21, 0x6a44, 0x4d85, { 0xb1, 0xe2, 0x38, 0x74, 0xc6, 0x5a, 0x0d, 0x91 } }

//
// CAN frame model (classic CAN, up to 8 data bytes)
//
typedef struct {
  UINT32    ArbitrationId;
  BOOLEAN   ExtendedId;
  BOOLEAN   Spoofed;
  UINT8     Dlc;
  UINT8     Data[CAN_MAX_DATA_LEN];
} CAN_FRAME;

//
// Simulated ECU node inventory
//
typedef struct {
  CONST CHAR8   *Name;
  UINT32        ArbitrationId;
  BOOLEAN       ExtendedId;
  BOOLEAN       SpoofTarget;
} CAN_ECU_NODE;

//
// Emulated bus statistics
//
typedef struct {
  UINT32    FramesTransmitted;
  UINT32    FramesReceived;
  UINT32    FramesDropped;
} CAN_STATS;

//
// Virtual CAN-over-UEFI protocol
//
typedef struct _BARZAKH_CAN_PROTOCOL BARZAKH_CAN_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *BARZAKH_CAN_TRANSMIT_FRAME) (
  IN BARZAKH_CAN_PROTOCOL  *This,
  IN CAN_FRAME             *Frame
  );

typedef
EFI_STATUS
(EFIAPI *BARZAKH_CAN_RECEIVE_FRAME) (
  IN BARZAKH_CAN_PROTOCOL  *This,
  OUT CAN_FRAME            *Frame
  );

typedef
EFI_STATUS
(EFIAPI *BARZAKH_CAN_GET_STATS) (
  IN BARZAKH_CAN_PROTOCOL  *This,
  OUT CAN_STATS            *Stats
  );

struct _BARZAKH_CAN_PROTOCOL {
  BARZAKH_CAN_TRANSMIT_FRAME  TransmitFrame;
  BARZAKH_CAN_RECEIVE_FRAME   ReceiveFrame;
  BARZAKH_CAN_GET_STATS       GetStats;
};

//
// Module state machine
//
typedef enum {
  CanStateInit = 0,
  CanStateBusEnumerated,
  CanStateProtocolInstalled,
  CanStateFramesInjected,
  CanStateComplete,
  CanStateError
} CAN_STATE;

//
// Module context
//
typedef struct {
  BOOLEAN               Initialized;
  CAN_STATE             State;

  // Simulated bus inventory
  UINT32                EcuCount;
  CAN_ECU_NODE          Ecus[CAN_MAX_ECUS];

  // Virtual protocol binding
  EFI_HANDLE            ProtocolHandle;
  BARZAKH_CAN_PROTOCOL  CanProtocol;

  // Injected frame ring buffer (simulation only)
  CAN_FRAME             InjectedFrames[CAN_MAX_INJECTED_FRAMES];
  UINT32                InjectedHead;
  UINT32                InjectedTail;
  UINT32                InjectedCount;

  // Emulated bus statistics
  CAN_STATS             Stats;
} CAN_INJECT_CONTEXT;

EFI_STATUS
EFIAPI
InitializeCanInject (
  OUT CAN_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EnumerateCanBus (
  IN OUT CAN_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InstallCanProtocol (
  IN OUT CAN_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectCanFrames (
  IN OUT CAN_INJECT_CONTEXT  *Context
  );

VOID
EFIAPI
LogCanInjectStatus (
  IN CAN_INJECT_CONTEXT  *Context
  );

#endif // AUTOMOTIVE_CAN_INJECT_H_
