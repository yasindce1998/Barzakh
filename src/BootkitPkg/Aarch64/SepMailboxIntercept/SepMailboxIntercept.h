/** @file
  SEP Mailbox Intercept Emulation - Header

  Models Apple Secure Enclave Processor (SEP) communication channel attacks.
  The AP communicates with SEP via a hardware mailbox (inbox/outbox FIFO).
  This module emulates intercepting key requests and responses to exfiltrate
  cryptographic material.

  All operations are SIMULATED - no actual SEP hardware is modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef SEP_MAILBOX_INTERCEPT_H_
#define SEP_MAILBOX_INTERCEPT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define SEP_DEBUG_PREFIX  "[SEP-Emu] "

//
// SEP mailbox base addresses (Apple Silicon)
//
#define SEP_MBOX_BASE           0x240000000ULL
#define SEP_MBOX_SIZE           0x00010000
#define SEP_INBOX_OFFSET        0x0000      // AP -> SEP messages
#define SEP_OUTBOX_OFFSET       0x4000      // SEP -> AP messages
#define SEP_STATUS_OFFSET       0x8000
#define SEP_CONTROL_OFFSET      0xC000

//
// Mailbox register offsets (within inbox/outbox)
//
#define SEP_MBOX_MSG_LO         0x00   // Message low 32 bits
#define SEP_MBOX_MSG_HI         0x04   // Message high 32 bits
#define SEP_MBOX_FLAGS          0x08   // Control flags
#define SEP_MBOX_FIFO_STATUS    0x0C   // FIFO empty/full status

//
// FIFO status bits
//
#define SEP_FIFO_EMPTY          BIT0
#define SEP_FIFO_FULL           BIT1
#define SEP_FIFO_OVERFLOW       BIT2

//
// SEP endpoint IDs
//
#define SEP_EP_CONTROL          0x00   // Control channel
#define SEP_EP_KEYSTORE         0x01   // Keystore operations
#define SEP_EP_BIOMETRIC        0x02   // Touch ID / Face ID
#define SEP_EP_SECURE_CRED      0x03   // Secure credential storage
#define SEP_EP_APPLE_PAY        0x04   // Payment tokens
#define SEP_EP_MAX              0x05

//
// SEP opcodes (within endpoint messages)
//
#define SEP_OP_INIT             0x01
#define SEP_OP_KEY_CREATE       0x10
#define SEP_OP_KEY_LOAD         0x11
#define SEP_OP_KEY_DELETE       0x12
#define SEP_OP_KEY_WRAP         0x13
#define SEP_OP_KEY_UNWRAP       0x14
#define SEP_OP_ENCRYPT          0x20
#define SEP_OP_DECRYPT          0x21
#define SEP_OP_SIGN             0x22
#define SEP_OP_VERIFY           0x23
#define SEP_OP_BIO_ENROLL       0x30
#define SEP_OP_BIO_MATCH       0x31
#define SEP_OP_RESPONSE         0x80
#define SEP_OP_ERROR            0xFF

//
// SEP message structure (8 bytes header + payload)
//
#define SEP_MSG_HEADER_SIZE     8
#define SEP_MSG_MAX_PAYLOAD     256

typedef struct {
  UINT8     Endpoint;
  UINT8     Opcode;
  UINT16    Tag;
  UINT16    PayloadLen;
  UINT16    Reserved;
  UINT8     Payload[SEP_MSG_MAX_PAYLOAD];
} SEP_MESSAGE;

//
// Maximum intercepted messages
//
#define SEP_MAX_INTERCEPTED     16

//
// Intercepted message record
//
typedef struct {
  SEP_MESSAGE   Message;
  BOOLEAN       IsInbound;    // TRUE = AP->SEP, FALSE = SEP->AP
  BOOLEAN       ContainsKey;
} SEP_INTERCEPT_RECORD;

//
// Simulated key material (for logging only)
//
#define SEP_SIM_KEY_SIZE        32  // 256-bit key

typedef struct {
  UINT8     KeyId;
  UINT8     KeyData[SEP_SIM_KEY_SIZE];
  UINT32    KeyLen;
  BOOLEAN   Exfiltrated;
} SEP_KEY_RECORD;

#define SEP_MAX_KEYS            4

typedef enum {
  SepStateUninitialized = 0,
  SepStateMailboxLocated,
  SepStateChannelMapped,
  SepStateMessageIntercepted,
  SepStateKeysExfiltrated
} SEP_STATE;

typedef struct {
  BOOLEAN             Initialized;
  SEP_STATE           State;

  // Mailbox location
  UINT64              MboxBase;
  UINT64              InboxAddr;
  UINT64              OutboxAddr;

  // Channel mapping
  UINT32              ActiveEndpoints;
  BOOLEAN             EndpointMapped[SEP_EP_MAX];

  // Intercepted messages
  SEP_INTERCEPT_RECORD  Intercepted[SEP_MAX_INTERCEPTED];
  UINT32              InterceptCount;

  // Exfiltrated keys
  SEP_KEY_RECORD      Keys[SEP_MAX_KEYS];
  UINT32              KeyCount;
  BOOLEAN             KeysExfiltrated;
} SEP_CONTEXT;

EFI_STATUS
EFIAPI
InitializeSepIntercept (
  OUT SEP_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateSepMailbox (
  IN OUT SEP_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
MapSepChannels (
  IN OUT SEP_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
InterceptSepMessages (
  IN OUT SEP_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ExfiltrateSepKeys (
  IN OUT SEP_CONTEXT  *Context
  );

VOID
EFIAPI
LogSepInterceptStatus (
  IN     SEP_CONTEXT  *Context
  );

#endif // SEP_MAILBOX_INTERCEPT_H_
