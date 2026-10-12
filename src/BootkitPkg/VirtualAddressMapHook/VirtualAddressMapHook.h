/** @file
  Virtual Address Map Hook Emulation - Header

  Models CosmicStrand-style kernel patching via SetVirtualAddressMap callbacks.
  Registers for EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE, scans memory for the Windows
  kernel PE header, and emulates DSE bypass patching during the OS handoff.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef VIRTUAL_ADDRESS_MAP_HOOK_H_
#define VIRTUAL_ADDRESS_MAP_HOOK_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <BarzakhMode.h>

#define VAM_DEBUG_PREFIX  "[VamHook-Emu] "

//
// PE/COFF signature constants
//
#define PE_DOS_SIGNATURE             0x5A4D      // "MZ"
#define PE_NT_SIGNATURE              0x00004550  // "PE\0\0"
#define PE_MACHINE_AMD64             0x8664

//
// Kernel search parameters
//
#define KERNEL_SEARCH_BASE           0xFFFFF80000000000ULL
#define KERNEL_SEARCH_LIMIT          0xFFFFF80040000000ULL
#define KERNEL_SEARCH_STEP           0x1000      // Page-aligned
#define KERNEL_EXPECTED_SIZE_MIN     0x00800000  // 8 MB minimum
#define KERNEL_EXPECTED_SIZE_MAX     0x02000000  // 32 MB maximum

//
// DSE (Driver Signature Enforcement) patch targets
//
#define DSE_CI_OPTIONS_OFFSET        0x00  // Placeholder - varies by build
#define DSE_PATCH_VALUE              0x00  // Disable enforcement

//
// Maximum patch sites
//
#define MAX_PATCH_SITES              8

typedef enum {
  VamStateUninitialized = 0,
  VamStateEventRegistered,
  VamStateCallbackFired,
  VamStateKernelFound,
  VamStatePatchApplied
} VAM_HOOK_STATE;

typedef enum {
  PatchTargetDse = 0,
  PatchTargetPatchGuard,
  PatchTargetCustom
} PATCH_TARGET_TYPE;

typedef struct {
  PATCH_TARGET_TYPE  Type;
  UINT64             Address;
  UINT32             OriginalSize;
  UINT8              OriginalBytes[16];
  UINT8              PatchBytes[16];
  UINT32             PatchSize;
  BOOLEAN            Applied;
} PATCH_SITE;

typedef struct {
  BOOLEAN         Initialized;
  VAM_HOOK_STATE  State;

  // Event registration
  EFI_EVENT       VamEvent;
  BOOLEAN         EventRegistered;
  BOOLEAN         CallbackFired;

  // Kernel discovery
  UINT64          KernelBase;
  UINT32          KernelSize;
  BOOLEAN         KernelFound;
  UINT16          Machine;
  UINT32          TimeDateStamp;

  // Patching state
  PATCH_SITE      PatchSites[MAX_PATCH_SITES];
  UINT32          PatchCount;
  UINT32          PatchesApplied;

  // Virtual address translation
  UINT64          PhysicalBase;
  UINT64          VirtualBase;
  BOOLEAN         AddressTranslated;
} VAM_HOOK_CONTEXT;

EFI_STATUS
EFIAPI
InitializeVamHook (
  OUT VAM_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
RegisterVamCallback (
  IN OUT VAM_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateCallbackFire (
  IN OUT VAM_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ScanForKernelImage (
  IN OUT VAM_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
PrepareKernelPatches (
  IN OUT VAM_HOOK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateKernelPatch (
  IN OUT VAM_HOOK_CONTEXT  *Context
  );

VOID
EFIAPI
LogVamHookStatus (
  IN     VAM_HOOK_CONTEXT  *Context
  );

#endif // VIRTUAL_ADDRESS_MAP_HOOK_H_
