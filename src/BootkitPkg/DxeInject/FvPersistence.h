/** @file
  FV-Based Persistence - Models Firmware Volume Payload Injection

  Emulates the technique where a bootkit injects a malicious FFS
  (Firmware File System) entry into free space within a Firmware
  Volume on SPI flash, achieving persistence that survives OS
  reinstall.

  Seen in: LoJax (2018), MosaicRegressor (2020), ESPecter (2021),
           BlackLotus FV variant (2023)

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __FV_PERSISTENCE_H__
#define __FV_PERSISTENCE_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Pi/PiFirmwareVolume.h>
#include <Pi/PiFirmwareFile.h>
#include <BarzakhMode.h>

//
// FFS File type for injection
//
#define FV_INJECT_TYPE_DXE_DRIVER  EFI_FV_FILETYPE_DRIVER
#define FV_INJECT_TYPE_DXE_CORE    EFI_FV_FILETYPE_DXE_CORE
#define FV_INJECT_TYPE_APPLICATION EFI_FV_FILETYPE_APPLICATION

//
// FV Persistence Context
//
typedef struct {
  BOOLEAN           Initialized;
  //
  // Target Firmware Volume
  //
  UINT32            FvBaseInFlash;       // FV start offset in SPI flash
  UINT32            FvSize;              // Total FV size
  UINT32            FvFreeSpaceOffset;   // Offset of free space within FV
  UINT32            FvFreeSpaceSize;     // Available free space bytes
  //
  // Injected payload tracking
  //
  EFI_GUID          InjectedFileGuid;    // GUID of the injected FFS file
  UINT32            InjectedFileSize;    // Size of injected file (header + payload)
  UINT8             InjectedFileType;    // EFI_FV_FILETYPE_*
  BOOLEAN           InjectionComplete;
  //
  // Integrity evasion
  //
  BOOLEAN           FvChecksumValid;     // Whether we fixed the FV header checksum
  UINT32            OriginalFvChecksum;  // Backup of original checksum
} FV_PERSISTENCE_CONTEXT;

/**
  Initialize FV Persistence context.

  @param[in,out]  Context     Pointer to persistence context.
  @param[in]      FvBase      Base offset of target FV in flash.
  @param[in]      FvSize      Size of target FV.

  @retval EFI_SUCCESS           Context initialized.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
EFI_STATUS
EFIAPI
InitializeFvPersistence (
  IN OUT FV_PERSISTENCE_CONTEXT  *Context,
  IN     UINT32                  FvBase,
  IN     UINT32                  FvSize
  );

/**
  Find free space in a Firmware Volume.

  Scans for 0xFF padding after the last valid FFS file entry.

  @param[in]   Context    Pointer to persistence context.
  @param[in]   FvData     Buffer containing FV data.
  @param[in]   FvDataSize Size of FV data buffer.
  @param[out]  FreeOffset Offset of free space (relative to FV start).
  @param[out]  FreeSize   Size of available free space.

  @retval EFI_SUCCESS     Free space found.
  @retval EFI_NOT_FOUND   No free space available.
**/
EFI_STATUS
EFIAPI
FindFvFreeSpace (
  IN  FV_PERSISTENCE_CONTEXT  *Context,
  IN  UINT8                   *FvData,
  IN  UINT32                  FvDataSize,
  OUT UINT32                  *FreeOffset,
  OUT UINT32                  *FreeSize
  );

/**
  Construct a valid FFS file header for injection.

  Builds an EFI_FFS_FILE_HEADER with correct type, size, checksum,
  and state bits so the DXE dispatcher will load it.

  @param[in]   FileGuid    GUID for the new FFS file.
  @param[in]   FileType    EFI_FV_FILETYPE_* value.
  @param[in]   PayloadSize Size of the payload data (excluding header).
  @param[out]  Header      Buffer to receive the constructed header.

  @retval EFI_SUCCESS           Header constructed.
  @retval EFI_INVALID_PARAMETER Invalid parameters.
**/
EFI_STATUS
EFIAPI
ConstructFfsHeader (
  IN  EFI_GUID             *FileGuid,
  IN  UINT8                FileType,
  IN  UINT32               PayloadSize,
  OUT EFI_FFS_FILE_HEADER  *Header
  );

/**
  Inject payload into FV free space (via SPI emulator).

  Writes constructed FFS file into the identified free space.
  This is a SIMULATION — actual writes go through the SPI flash
  emulator which logs the operation.

  @param[in]  Context      Pointer to persistence context.
  @param[in]  Payload      Payload data to inject.
  @param[in]  PayloadSize  Size of payload.
  @param[in]  FlashBuffer  The emulated flash buffer to write into.
  @param[in]  FlashSize    Total flash buffer size.

  @retval EFI_SUCCESS           Injection complete (or simulated).
  @retval EFI_BUFFER_TOO_SMALL  Payload exceeds free space.
**/
EFI_STATUS
EFIAPI
InjectFvPayload (
  IN FV_PERSISTENCE_CONTEXT  *Context,
  IN UINT8                   *Payload,
  IN UINT32                  PayloadSize,
  IN UINT8                   *FlashBuffer,
  IN UINT32                  FlashSize
  );

/**
  Validate and fix FV header integrity after injection.

  Recalculates the FV header checksum so basic integrity scanners
  won't flag the modified volume.

  @param[in]  Context      Pointer to persistence context.
  @param[in]  FlashBuffer  The emulated flash buffer.
  @param[in]  FlashSize    Total flash buffer size.

  @retval EFI_SUCCESS  Checksum recalculated.
**/
EFI_STATUS
EFIAPI
ValidateFvIntegrity (
  IN FV_PERSISTENCE_CONTEXT  *Context,
  IN UINT8                   *FlashBuffer,
  IN UINT32                  FlashSize
  );

/**
  Log FV persistence status.

  @param[in]  Context  Pointer to persistence context.
**/
VOID
EFIAPI
LogFvPersistenceStatus (
  IN FV_PERSISTENCE_CONTEXT  *Context
  );

#endif // __FV_PERSISTENCE_H__
