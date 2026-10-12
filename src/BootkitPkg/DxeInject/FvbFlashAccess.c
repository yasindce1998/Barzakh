/** @file
  Real FVB2 Flash Access - Implementation

  Functional-build flash backend. Routes the SPI flash emulator's
  erase/write operations through the EFI_FIRMWARE_VOLUME_BLOCK2
  protocol — the same path real LoJax/MoonBounce-style implants use
  for firmware persistence.

  In simulation builds (the default) these functions are never called;
  the emulator's in-RAM shadow buffer is used instead.

  FVB2 programming rules (PI spec vol 3):
    - EraseBlocks/Write operate at TPL_NOTIFY or below; we serialize
      with a TPL_CALLBACK raise around each call.
    - Writes may only clear bits (1->0) on erased (0xFF) blocks; the
      caller must erase first, which the emulator's write path does.
    - Blocks may be non-uniform; GetBlockSize() walks runs of equal
      block size, so the offset->Lba mapping walks those runs.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "FvbFlashAccess.h"
#include <Library/UefiLib.h>

#define FVB_ACCESS_DEBUG_PREFIX  "[FVB2] "

//
// Cached FVB2 protocol pointer (single flash device model).
//
STATIC EFI_FIRMWARE_VOLUME_BLOCK2_PROTOCOL  *mFvb = NULL;

/**
  Locate the FVB2 protocol for the boot firmware volume.

  @retval EFI_SUCCESS     Protocol located (or already cached).
  @retval EFI_NOT_FOUND   No FVB2 protocol instance is available.
**/
EFI_STATUS
EFIAPI
FvbLocate (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mFvb != NULL) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (
                  &gEfiFirmwareVolumeBlock2ProtocolGuid,
                  NULL,
                  (VOID **)&mFvb
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_WARN, FVB_ACCESS_DEBUG_PREFIX "No FVB2 protocol: %r\n", Status));
    return EFI_NOT_FOUND;
  }

  DEBUG ((DEBUG_INFO, FVB_ACCESS_DEBUG_PREFIX "FVB2 protocol located\n"));
  return EFI_SUCCESS;
}

/**
  Map a linear flash offset to (Lba, offset-in-block).

  Walks the FVB2 block-size runs reported by GetBlockSize() until the
  run containing Offset is found. Total addressable flash is capped by
  MAX_FVB_LBAS blocks as a safety limit.

  @param[in]   Offset    Linear flash offset.
  @param[out]  Lba       Logical block address.
  @param[out]  InBlock   Byte offset within the block.

  @retval EFI_SUCCESS     Mapping found.
  @retval EFI_NOT_FOUND   Offset lies beyond the FVB2 address space.
  @retval EFI_NOT_READY   FVB2 not located yet.
**/
STATIC
EFI_STATUS
FvbOffsetToLba (
  IN  UINT32    Offset,
  OUT EFI_LBA   *Lba,
  OUT UINTN     *InBlock
  )
{
  EFI_STATUS  Status;
  EFI_LBA     CandidateLba;
  UINTN       BlockSize;
  UINT32      NumberOfBlocks;
  UINT64      Remaining;
  UINT64      RunBytes;

  if (mFvb == NULL) {
    return EFI_NOT_READY;
  }

  Remaining    = Offset;
  CandidateLba = 0;

  while (CandidateLba < MAX_FVB_LBAS) {
    Status = mFvb->GetBlockSize (mFvb, CandidateLba, &BlockSize, &NumberOfBlocks);
    if (EFI_ERROR (Status) || BlockSize == 0 || NumberOfBlocks == 0) {
      break;  // past the last block run
    }

    RunBytes = (UINT64)BlockSize * (UINT64)NumberOfBlocks;

    if (Remaining < RunBytes) {
      *Lba      = CandidateLba + (Remaining / BlockSize);
      *InBlock  = (UINTN)(Remaining % BlockSize);
      return EFI_SUCCESS;
    }

    Remaining    -= RunBytes;
    CandidateLba += NumberOfBlocks;
  }

  return EFI_NOT_FOUND;
}

/**
  Erase a flash range via FVB2. Erases every block that overlaps
  [Offset, Offset+Size).

  @param[in]  Offset  Linear flash offset to erase from.
  @param[in]  Size    Number of bytes to erase.

  @retval EFI_SUCCESS     Range erased.
  @retval EFI_NOT_READY   FVB2 not located.
  @retval Others          Erase failed or range unmapped.
**/
EFI_STATUS
EFIAPI
FvbEraseRange (
  IN UINT32  Offset,
  IN UINT32  Size
  )
{
  EFI_STATUS  Status;
  EFI_LBA     StartLba;
  EFI_LBA     EndLba;
  EFI_LBA     Lba;
  UINTN       InBlock;
  EFI_TPL     OldTpl;

  if (mFvb == NULL) {
    return EFI_NOT_READY;
  }

  Status = FvbOffsetToLba (Offset, &StartLba, &InBlock);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FVB_ACCESS_DEBUG_PREFIX "Erase offset 0x%x unmapped\n", Offset));
    return Status;
  }

  Status = FvbOffsetToLba (Offset + Size - 1, &EndLba, &InBlock);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, FVB_ACCESS_DEBUG_PREFIX "Erase end 0x%x unmapped\n", Offset + Size - 1));
    return Status;
  }

  //
  // Erase is block-granular: the [Offset, Offset+Size) range covers
  // every block from StartLba through EndLba inclusive. Unaligned
  // ranges destroy up to one extra block on each side — the caller
  // (emulator/FV persistence) only issues block-aligned erases.
  //
  if ((InBlock != 0) || ((Size % FVB_BLOCK_SIZE) != 0)) {
    DEBUG ((
      DEBUG_WARN,
      FVB_ACCESS_DEBUG_PREFIX "Unaligned erase 0x%x+0x%x — extending to block boundary\n",
      Offset,
      Size
      ));
  }

  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);

  for (Lba = StartLba; Lba <= EndLba; Lba++) {
    //
    // EraseBlocks is variadic: (This, Lba, NumBlocks, ...,
    // EFI_LBA_LIST_TERMINATOR).
    //
    Status = mFvb->EraseBlocks (mFvb, Lba, 1, EFI_LBA_LIST_TERMINATOR);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, FVB_ACCESS_DEBUG_PREFIX "Erase Lba %lu failed: %r\n", (UINT64)Lba, Status));
      gBS->RestoreTPL (OldTpl);
      return Status;
    }
  }

  gBS->RestoreTPL (OldTpl);

  DEBUG ((
    DEBUG_INFO,
    FVB_ACCESS_DEBUG_PREFIX "Erased 0x%x+0x%x (Lba %lu..%lu)\n",
    Offset,
    Size,
    (UINT64)StartLba,
    (UINT64)EndLba
    ));
  return EFI_SUCCESS;
}

/**
  Write a flash range via FVB2. The range must already be erased.

  @param[in]  Offset  Linear flash offset to write to.
  @param[in]  Size    Number of bytes to write.
  @param[in]  Buffer  Data to write.

  @retval EFI_SUCCESS     Range written.
  @retval EFI_NOT_READY   FVB2 not located.
  @retval Others          Write failed or range unmapped.
**/
EFI_STATUS
EFIAPI
FvbWriteRange (
  IN UINT32  Offset,
  IN UINT32  Size,
  IN UINT8   *Buffer
  )
{
  EFI_STATUS  Status;
  EFI_LBA     Lba;
  UINTN       InBlock;
  UINTN       Chunk;
  UINT32      Done;
  EFI_TPL     OldTpl;

  if (mFvb == NULL) {
    return EFI_NOT_READY;
  }

  Done = 0;
  while (Done < Size) {
    Status = FvbOffsetToLba (Offset + Done, &Lba, &InBlock);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, FVB_ACCESS_DEBUG_PREFIX "Write offset 0x%x unmapped\n", Offset + Done));
      return Status;
    }

    Chunk = FVB_BLOCK_SIZE - InBlock;
    if (Chunk > (Size - Done)) {
      Chunk = Size - Done;
    }

    OldTpl = gBS->RaiseTPL (TPL_CALLBACK);
    Status = mFvb->Write (
                     mFvb,
                     Lba,
                     InBlock,
                     &Chunk,
                     Buffer + Done
                     );
    gBS->RestoreTPL (OldTpl);

    if (EFI_ERROR (Status)) {
      DEBUG ((
        DEBUG_ERROR,
        FVB_ACCESS_DEBUG_PREFIX "Write Lba %lu +0x%x failed: %r\n",
        (UINT64)Lba,
        InBlock,
        Status
        ));
      return Status;
    }

    Done += (UINT32)Chunk;
  }

  DEBUG ((DEBUG_INFO, FVB_ACCESS_DEBUG_PREFIX "Wrote 0x%x bytes at 0x%x\n", Size, Offset));
  return EFI_SUCCESS;
}
