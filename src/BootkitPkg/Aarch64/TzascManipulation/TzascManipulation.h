/** @file
  TrustZone Address Space Controller Manipulation - Header

  Models TZC-400 (TrustZone Address Space Controller) manipulation to
  repartition secure/non-secure memory regions. Demonstrates how an attacker
  with EL3 access can break TrustZone isolation by modifying region attributes.

  All operations are SIMULATED - no actual TZASC registers are modified.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef TZASC_MANIPULATION_H_
#define TZASC_MANIPULATION_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <BarzakhMode.h>

#define TZASC_DEBUG_PREFIX  "[TZASC-Emu] "

//
// TZC-400 base address (typical ARM platform)
//
#define TZC400_BASE_ADDRESS     0x2A4A0000

//
// TZC-400 register offsets
//
#define TZC_BUILD_CONFIG        0x000
#define TZC_ACTION              0x004
#define TZC_GATE_KEEPER         0x008
#define TZC_SPECULATION_CTRL    0x00C
#define TZC_INT_STATUS          0x010
#define TZC_INT_CLEAR           0x014

//
// Region register offsets (base + 0x100 + region_number * 0x20)
//
#define TZC_REGION_BASE_LOW(n)   (0x100 + (n) * 0x20 + 0x00)
#define TZC_REGION_BASE_HIGH(n)  (0x100 + (n) * 0x20 + 0x04)
#define TZC_REGION_TOP_LOW(n)    (0x100 + (n) * 0x20 + 0x08)
#define TZC_REGION_TOP_HIGH(n)   (0x100 + (n) * 0x20 + 0x0C)
#define TZC_REGION_ATTRIBUTES(n) (0x100 + (n) * 0x20 + 0x10)
#define TZC_REGION_ID_ACCESS(n)  (0x100 + (n) * 0x20 + 0x14)

//
// Region attribute bit fields
//
#define TZC_ATTR_FILTER_EN(f)    ((UINT32)1 << (f))
#define TZC_ATTR_S_RD_EN         BIT30  // Secure read enable
#define TZC_ATTR_S_WR_EN         BIT31  // Secure write enable

//
// Non-secure access ID permissions (bits [19:0] of REGION_ID_ACCESS)
//
#define TZC_NSAID_RD_EN(id)      ((UINT32)1 << ((id) * 2))
#define TZC_NSAID_WR_EN(id)      ((UINT32)1 << ((id) * 2 + 1))
#define TZC_NSAID_NONE           0x00000000
#define TZC_NSAID_ALL_RW         0x000FFFFF

//
// Security states for region
//
#define TZC_SEC_SECURE_ONLY      0  // Only secure access allowed
#define TZC_SEC_NS_RD            1  // Non-secure read allowed
#define TZC_SEC_NS_WR            2  // Non-secure write allowed
#define TZC_SEC_NS_RW            3  // Non-secure read+write

//
// Maximum regions supported by TZC-400
//
#define TZC_MAX_REGIONS          9

//
// Simulated memory regions
//
#define TZASC_DRAM_BASE          0x80000000
#define TZASC_SECURE_BASE        0x8E000000
#define TZASC_SECURE_SIZE        0x02000000  // 32MB secure region

typedef struct {
  UINT64    BaseLow;
  UINT64    BaseHigh;
  UINT64    TopLow;
  UINT64    TopHigh;
  UINT32    Attributes;
  UINT32    IdAccess;
  BOOLEAN   IsSecure;
} TZASC_REGION_INFO;

typedef enum {
  TzascStateUninitialized = 0,
  TzascStateTzascLocated,
  TzascStateRegionsMapped,
  TzascStateRegionModified,
  TzascStateAccessGranted
} TZASC_STATE;

typedef struct {
  BOOLEAN           Initialized;
  TZASC_STATE       State;

  // Controller info
  UINT64            TzascBase;
  UINT32            NumRegions;
  UINT32            NumFilters;

  // Region map
  TZASC_REGION_INFO Regions[TZC_MAX_REGIONS];
  UINT32            SecureRegionIndex;

  // Attack state
  UINT32            OriginalAttributes;
  UINT32            OriginalIdAccess;
  UINT32            ModifiedAttributes;
  UINT32            ModifiedIdAccess;
  BOOLEAN           IsolationBroken;
} TZASC_CONTEXT;

EFI_STATUS
EFIAPI
InitializeTzasc (
  OUT TZASC_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
LocateTzascController (
  IN OUT TZASC_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
MapTzascRegions (
  IN OUT TZASC_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ModifySecureRegion (
  IN OUT TZASC_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
VerifyNonSecureAccess (
  IN OUT TZASC_CONTEXT  *Context
  );

VOID
EFIAPI
LogTzascStatus (
  IN     TZASC_CONTEXT  *Context
  );

#endif // TZASC_MANIPULATION_H_
