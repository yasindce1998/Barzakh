/** @file
  NVIDIA Security Processor Command Forge Emulation - Header

  Models forged commands sent to the NVIDIA Security Processor (NSP),
  in the same spirit as the FtpmCommandForge module for AMD fTPM.
  The NSP owns the Security Engine keyslots; this module emulates
  secure-mailbox redirect (so forged responses reach the host read
  path) and keyslot dump extraction.

  All operations are SIMULATED - no NSP mailbox or keyslot is ever
  modified, and no key material exists outside simulated buffers.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef NSP_COMMAND_FORGE_H_
#define NSP_COMMAND_FORGE_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <BarzakhMode.h>

#define NSP_DEBUG_PREFIX  "[NSP-Emu] "

//
// Time-bomb expiry (kill-switch). Matches the project-wide default.
//
#ifndef BARZAKH_EXPIRY_DATE
#define BARZAKH_EXPIRY_DATE  "2027-05-11"
#endif

//
// Simulated NSP secure mailbox layout (research model)
//
#define NSP_MBOX_BASE            0x01C0000000ULL
#define NSP_MBOX_SIZE            0x00010000
#define NSP_MBOX_CMD_OFFSET      0x0000      // Host -> NSP commands
#define NSP_MBOX_RSP_OFFSET      0x4000      // NSP -> host responses
#define NSP_MBOX_STATUS_OFFSET   0x8000
#define NSP_EXFIL_BUFFER         0x880000000ULL   // Attacker DRAM staging

//
// NSP command opcodes (research model)
//
#define NSP_CMD_GET_VERSION      0x01
#define NSP_CMD_KEYSLOT_READ     0x21
#define NSP_CMD_KEYSLOT_EXPORT   0x22

//
// Simulated keyslot table
//
#define NSP_MAX_KEYSLOTS         16
#define NSP_SIM_KEY_SIZE         32    // 256-bit key model

//
// Maximum forged commands
//
#define NSP_MAX_FORGED           4

//
// Forged command record
//
typedef struct {
  UINT32    Opcode;
  UINT32    KeyslotIndex;
  UINT32    KeySize;
  BOOLEAN   Forged;
} NSP_FORGED_COMMAND;

//
// Keyslot record (simulated material, for logging only)
//
typedef struct {
  UINT8     SlotIndex;
  UINT32    KeySize;
  UINT8     KeyData[NSP_SIM_KEY_SIZE];
  BOOLEAN   Dumped;
} NSP_KEYSLOT_RECORD;

//
// Module state machine
//
typedef enum {
  NspStateInit = 0,
  NspStateMailboxLocated,
  NspStateMailboxRedirected,
  NspStateCommandsForged,
  NspStateKeyslotsDumped,
  NspStateError
} NSP_STATE;

//
// Module context
//
typedef struct {
  BOOLEAN               Initialized;
  NSP_STATE             State;

  // Secure mailbox location
  UINT64                MboxBase;
  UINT64                CmdBuffer;
  UINT64                RspBuffer;
  UINT64                RedirectedRspBuffer;
  BOOLEAN               MailboxRedirected;

  // Forged commands
  NSP_FORGED_COMMAND    ForgedCommands[NSP_MAX_FORGED];
  UINT32                ForgedCommandCount;

  // Dumped keyslots
  NSP_KEYSLOT_RECORD    Keyslots[NSP_MAX_KEYSLOTS];
  UINT32                KeyslotCount;
} NSP_FORGE_CONTEXT;

EFI_STATUS
EFIAPI
InitializeNspForge (
  OUT NSP_FORGE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateNspSecureMailbox (
  IN OUT NSP_FORGE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
RedirectSecureMailbox (
  IN OUT NSP_FORGE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ForgeNspCommands (
  IN OUT NSP_FORGE_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateKeyslotDump (
  IN OUT NSP_FORGE_CONTEXT  *Context
  );

VOID
EFIAPI
LogNspForgeStatus (
  IN NSP_FORGE_CONTEXT  *Context
  );

#endif // NSP_COMMAND_FORGE_H_
