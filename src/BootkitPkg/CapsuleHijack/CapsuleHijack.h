/** @file
  Capsule Update Hijack Emulation - Header

  Models firmware update protocol abuse techniques. Enumerates FMP instances,
  constructs malicious capsule headers, and simulates SetImage/UpdateCapsule
  injection for persistence across firmware updates.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef CAPSULE_HIJACK_H_
#define CAPSULE_HIJACK_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/FirmwareManagement.h>
#include <BarzakhMode.h>

#define CAPSULE_DEBUG_PREFIX  "[Capsule-Emu] "

//
// Capsule header flags
//
#define CAPSULE_FLAGS_PERSIST_ACROSS_RESET   0x00010000
#define CAPSULE_FLAGS_INITIATE_RESET         0x00040000

//
// Maximum FMP instances to enumerate
//
#define MAX_FMP_INSTANCES        8

//
// Malicious capsule payload marker
//
#define IMPLANT_MARKER           0xDEADC0DE

//
// Simulated image sizes
//
#define SIMULATED_IMAGE_SIZE     0x00100000  // 1 MB
#define CAPSULE_HEADER_SIZE      sizeof(EFI_CAPSULE_HEADER)

typedef enum {
  CapsuleStateUninitialized = 0,
  CapsuleStateFmpEnumerated,
  CapsuleStateImageInfoGathered,
  CapsuleStateCapsuleConstructed,
  CapsuleStateInjectionSimulated
} CAPSULE_HIJACK_STATE;

typedef struct {
  EFI_GUID  ImageTypeId;
  UINT8     ImageIndex;
  UINT64    ImageSize;
  UINT64    AttributesSupported;
  UINT64    AttributesSetting;
  UINT32    Version;
  CHAR16    ImageIdName[64];
  BOOLEAN   Updatable;
} FMP_IMAGE_INFO_ENTRY;

typedef struct {
  BOOLEAN              Initialized;
  CAPSULE_HIJACK_STATE State;

  // FMP enumeration
  UINT32               FmpCount;
  EFI_HANDLE           FmpHandles[MAX_FMP_INSTANCES];
  FMP_IMAGE_INFO_ENTRY ImageInfo[MAX_FMP_INSTANCES];

  // Capsule construction
  UINT8                *CapsuleBuffer;
  UINT32               CapsuleSize;
  BOOLEAN              CapsuleReady;

  // Injection state
  BOOLEAN              SetImageAttempted;
  BOOLEAN              UpdateCapsuleAttempted;
  EFI_STATUS           InjectionResult;
} CAPSULE_HIJACK_CONTEXT;

EFI_STATUS
EFIAPI
InitializeCapsuleHijack (
  OUT CAPSULE_HIJACK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EnumerateFmpInstances (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
GatherImageInfo (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
ConstructMaliciousCapsule (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateSetImageInjection (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  );

EFI_STATUS
EFIAPI
EmulateUpdateCapsuleCall (
  IN OUT CAPSULE_HIJACK_CONTEXT  *Context
  );

VOID
EFIAPI
LogCapsuleHijackStatus (
  IN     CAPSULE_HIJACK_CONTEXT  *Context
  );

#endif // CAPSULE_HIJACK_H_
