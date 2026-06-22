/** @file
  fTPM Command Forge Emulation - Header

  Models AMD firmware TPM (fTPM) command forgery attacks against the Platform
  Security Processor (PSP). The fTPM runs as a trusted application inside the
  PSP, communicating with the host via a shared command/response buffer in
  MMIO space. This module emulates forging TPM2 commands and injecting
  crafted responses to subvert PCR-based measurements.

  All operations are SIMULATED - no actual PSP/fTPM hardware is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef FTPM_COMMAND_FORGE_H_
#define FTPM_COMMAND_FORGE_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define SIMULATION_MODE  TRUE

#define FTPM_DEBUG_PREFIX  "[fTPM-Emu] "

//
// PSP/fTPM MMIO addresses (AMD platforms)
//
#define PSP_MMIO_BASE            0xFED80000ULL
#define C2P_MSG_OFFSET           0x10570     // Command-to-PSP message offset
#define P2C_MSG_OFFSET           0x10670     // PSP-to-Command response offset
#define FTPM_CMD_BUFFER_SIZE     0x1000      // 4KB command buffer
#define FTPM_RESP_BUFFER_SIZE    0x1000      // 4KB response buffer

//
// TPM2 command/response structure codes
//
#define TPM2_ST_NO_SESSIONS      0x8001
#define TPM2_ST_SESSIONS         0x8002

//
// TPM2 command codes (subset relevant to PCR manipulation)
//
#define TPM2_CC_PCR_EXTEND       0x00000182
#define TPM2_CC_PCR_READ         0x0000017E
#define TPM2_CC_GET_RANDOM       0x0000017B

//
// TPM2 response codes
//
#define TPM2_RC_SUCCESS          0x000

//
// TPM2 command header (10 bytes)
//
typedef struct {
  UINT16    Tag;
  UINT32    CommandSize;
  UINT32    CommandCode;
} TPM2_COMMAND_HEADER;

//
// TPM2 response header (10 bytes)
//
typedef struct {
  UINT16    Tag;
  UINT32    ResponseSize;
  UINT32    ResponseCode;
} TPM2_RESPONSE_HEADER;

//
// Maximum forged commands/responses
//
#define FTPM_MAX_FORGED          4

//
// Forged command record
//
typedef struct {
  UINT32    CommandCode;
  UINT32    PcrIndex;
  UINT16    DigestSize;
} FTPM_FORGED_COMMAND;

//
// Forged response record
//
typedef struct {
  UINT32    ResponseCode;
  BOOLEAN   Validated;
} FTPM_FORGED_RESPONSE;

typedef enum {
  FtpmStateInit = 0,
  FtpmStateLocated,
  FtpmStateCommandForged,
  FtpmStateResponseInjected,
  FtpmStateComplete,
  FtpmStateError
} FTPM_STATE;

typedef struct {
  BOOLEAN               Initialized;
  FTPM_STATE            State;

  // PSP mailbox location
  UINT64                PspMmioBase;
  UINT64                C2pBuffer;
  UINT64                P2cBuffer;

  // Forged commands
  FTPM_FORGED_COMMAND   ForgedCommands[FTPM_MAX_FORGED];
  UINT32                ForgedCommandCount;

  // Forged responses
  FTPM_FORGED_RESPONSE  ForgedResponses[FTPM_MAX_FORGED];
  UINT32                ForgedResponseCount;
} FTPM_CONTEXT;

EFI_STATUS
EFIAPI
InitializeFtpmForge (
  OUT FTPM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateFtpmMailbox (
  IN OUT FTPM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ForgeCommand (
  IN OUT FTPM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InjectResponse (
  IN OUT FTPM_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ValidateFtpmForge (
  IN OUT FTPM_CONTEXT  *Context
  );

VOID
EFIAPI
LogFtpmForgeStatus (
  IN FTPM_CONTEXT  *Context
  );

#endif // FTPM_COMMAND_FORGE_H_
