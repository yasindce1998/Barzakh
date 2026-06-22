/** @file
  AMT Serial-over-LAN Channel Emulation - Header

  Models covert Command & Control (C2) communication over Intel Active
  Management Technology (AMT) Serial-over-LAN (SOL). This technique abuses
  the out-of-band management channel that operates independently of the OS,
  making it invisible to host-based security tools (Platinum APT technique).

  All operations are SIMULATED - no actual AMT hardware is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef AMT_SOL_CHANNEL_H_
#define AMT_SOL_CHANNEL_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define SIMULATION_MODE  TRUE

#define AMT_DEBUG_PREFIX  "[AMT-SOL-Emu] "

//
// Intel AMT/SOL PCI device location (MEI controller function 3)
//
#define AMT_SOL_PCI_BUS         0
#define AMT_SOL_PCI_DEV         22
#define AMT_SOL_PCI_FUN         3

//
// SOL MMIO register offsets
//
#define SOL_RECV_CTRL           0x00
#define SOL_SEND_CTRL           0x04
#define SOL_STATUS_REG          0x08

//
// AMT-specific register offsets
//
#define AMT_STATUS_REG          0x40
#define AMT_PROVISIONING_STATE  0x44

//
// SOL MMIO region size
//
#define SOL_MMIO_SIZE           0x2000

//
// AMT provisioning state values
//
#define AMT_PROVISION_COMPLETE  0x03

//
// C2 command structure (received over SOL channel)
//
typedef struct {
  UINT8     CommandId;
  UINT16    PayloadSize;
  UINT8     Payload[256];
} AMT_C2_COMMAND;

//
// Maximum commands/responses tracked
//
#define AMT_MAX_COMMANDS        8

//
// Module state machine
//
typedef enum {
  AmtStateInit = 0,
  AmtStateLocated,
  AmtStateProvisioned,
  AmtStateC2Active,
  AmtStateComplete,
  AmtStateError
} AMT_STATE;

//
// Module context
//
typedef struct {
  BOOLEAN         Initialized;
  AMT_STATE       State;

  // AMT device location
  UINT64          SolMmioBase;
  UINT32          ProvisioningState;

  // C2 channel tracking
  struct {
    AMT_C2_COMMAND  Commands[AMT_MAX_COMMANDS];
    UINT32          Count;
  } ReceivedCommands;

  struct {
    AMT_C2_COMMAND  Commands[AMT_MAX_COMMANDS];
    UINT32          Count;
  } SentResponses;

  // Exfiltration metrics
  UINT32          BytesExfiltrated;
} AMT_SOL_CONTEXT;

EFI_STATUS
EFIAPI
InitializeAmtSolChannel (
  OUT AMT_SOL_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateAmtDevice (
  IN OUT AMT_SOL_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InitializeSolChannel (
  IN OUT AMT_SOL_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EstablishC2Channel (
  IN OUT AMT_SOL_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ExfiltrateOverSol (
  IN OUT AMT_SOL_CONTEXT  *Context
  );

VOID
EFIAPI
LogAmtSolStatus (
  IN AMT_SOL_CONTEXT  *Context
  );

#endif // AMT_SOL_CHANNEL_H_
