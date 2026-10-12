/** @file
  Real FVB2 Flash Access - Header

  Functional-build flash backend for the SPI flash emulator. See
  FvbFlashAccess.c for details. Simulation builds never call these.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __FVB_FLASH_ACCESS_H__
#define __FVB_FLASH_ACCESS_H__

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/FirmwareVolumeBlock.h>
#include <BarzakhMode.h>

//
// Typical SPI NOR erase-block size (4KB). Used only for alignment
// sanity checks — actual block geometry comes from FVB2 GetBlockSize().
//
#define FVB_BLOCK_SIZE  0x1000

//
// Safety cap for the Lba walk (16MB flash / 4KB blocks).
//
#define MAX_FVB_LBAS  (16 * 1024 * 1024 / FVB_BLOCK_SIZE)

EFI_STATUS
EFIAPI
FvbLocate (
  VOID
  );

EFI_STATUS
EFIAPI
FvbEraseRange (
  IN UINT32  Offset,
  IN UINT32  Size
  );

EFI_STATUS
EFIAPI
FvbWriteRange (
  IN UINT32  Offset,
  IN UINT32  Size,
  IN UINT8   *Buffer
  );

#endif // __FVB_FLASH_ACCESS_H__
