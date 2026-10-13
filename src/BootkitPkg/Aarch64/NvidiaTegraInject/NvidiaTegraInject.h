/** @file
  NVIDIA Tegra Boot Chain Implant Emulation - Header

  Models a boot chain implant on NVIDIA Tegra-class SoCs (Ring -3):
  MB1/BPMP stage hooking, public-key (PKC) hash override, and Security
  Engine (SE) flash-skip emulation. The Tegra chain is BootROM -> MB1 ->
  MB2 -> BPMP-FW -> CPU bootloader; an implant that hooks early stages
  executes below every software layer the OS can inspect.

  All operations are SIMULATED - no fuse, SE register, or boot stage is
  ever modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef NVIDIA_TEGRA_INJECT_H_
#define NVIDIA_TEGRA_INJECT_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <BarzakhMode.h>

#define TEGRA_DEBUG_PREFIX  "[Tegra-Emu] "

//
// Time-bomb expiry (kill-switch). Matches the project-wide default.
//
#ifndef BARZAKH_EXPIRY_DATE
#define BARZAKH_EXPIRY_DATE  "2027-05-11"
#endif

//
// Simulated Tegra boot chain layout (Tegra X1-class research model)
//
#define TEGRA_BOOTROM_ENTRY     0xFFFF0000ULL   // Mask ROM
#define TEGRA_MB1_ENTRY         0x00100000ULL   // Bootloader stage 1
#define TEGRA_MB2_ENTRY         0x01000000ULL   // TegraBoot (stage 2)
#define TEGRA_BPMP_ENTRY        0x03000000ULL   // BPMP firmware
#define TEGRA_CPU_BL_ENTRY      0x80000000ULL   // CPU bootloader (BL31/uboot)
#define TEGRA_IMPLANT_TRAMPOLINE_BASE  0x00100200ULL

//
// Simulated SoC block addresses
//
#define TEGRA_FUSE_BASE         0x7000F800ULL   // Fuse controller
#define TEGRA_SE_BASE           0x70012000ULL   // Security Engine

//
// PKC hash model (SHA-256 over the OEM public key)
//
#define TEGRA_PKC_HASH_SIZE     32

//
// Table sizes
//
#define TEGRA_MAX_STAGES        6
#define TEGRA_MAX_SE_OPS        8

//
// Boot stage model
//
typedef struct {
  CONST CHAR8   *StageName;
  UINT64        EntryAddress;
  UINT64        OriginalEntry;
  UINT64        HookedEntry;
  BOOLEAN       Hooked;
} TEGRA_STAGE;

//
// Public-key hash override model
//
typedef struct {
  UINT8     OriginalHash[TEGRA_PKC_HASH_SIZE];
  UINT8     ForgedHash[TEGRA_PKC_HASH_SIZE];
  BOOLEAN   Overridden;
} TEGRA_PKC_OVERRIDE;

//
// Security Engine operation model
//
typedef struct {
  UINT32    Opcode;
  UINT32    SlotIndex;
  BOOLEAN   Skipped;
} TEGRA_SE_OP;

//
// SE opcodes (research model)
//
#define TEGRA_SE_OP_VERIFY_RSA   0x11
#define TEGRA_SE_OP_VERIFY_AES_CMAC  0x14
#define TEGRA_SE_OP_DECRYPT_PKC1  0x21

//
// Module state machine
//
typedef enum {
  TegraStateInit = 0,
  TegraStateChainMapped,
  TegraStateStagesHooked,
  TegraStatePkOverridden,
  TegraStateSeBypassed,
  TegraStateError
} TEGRA_STATE;

//
// Module context
//
typedef struct {
  BOOLEAN             Initialized;
  TEGRA_STATE         State;

  // Boot chain model
  UINT32              StageCount;
  TEGRA_STAGE         Stages[TEGRA_MAX_STAGES];

  // PKC hash override model
  TEGRA_PKC_OVERRIDE  PkcOverride;

  // SE flash-skip model
  UINT32              SeOpCount;
  TEGRA_SE_OP         SeOps[TEGRA_MAX_SE_OPS];
} TEGRA_INJECT_CONTEXT;

EFI_STATUS
EFIAPI
InitializeTegraInject (
  OUT TEGRA_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ModelTegraBootChain (
  IN OUT TEGRA_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
HookBootStages (
  IN OUT TEGRA_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
OverridePkHash (
  IN OUT TEGRA_INJECT_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateSeFlashSkip (
  IN OUT TEGRA_INJECT_CONTEXT  *Context
  );

VOID
EFIAPI
LogTegraInjectStatus (
  IN TEGRA_INJECT_CONTEXT  *Context
  );

#endif // NVIDIA_TEGRA_INJECT_H_
