/** @file
  ME DMA Attack Emulation - Header

  Simulates Intel Management Engine's independent DMA engine accessing
  host memory. The ME has its own DMA controller that can read/write
  host physical memory independently of the host CPU, bypassing OS
  security boundaries.

  All operations are SIMULATED - no actual hardware access occurs.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef ME_DMA_ATTACK_H_
#define ME_DMA_ATTACK_H_

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

//
// Simulation mode flag - all hardware access is emulated
//
#define SIMULATION_MODE  TRUE

//
// Debug prefix for all module logging
//
#define MEDMA_DEBUG_PREFIX  "[ME-DMA-Emu] "

//
// ME DMA Controller Register Definitions
//
#define ME_UMA_BASE_REG       0x7890
#define ME_DMA_CTRL_OFFSET    0x00
#define ME_DMA_SRC_OFFSET     0x08
#define ME_DMA_DST_OFFSET     0x10
#define ME_DMA_LEN_OFFSET     0x18
#define ME_DMA_STATUS_OFFSET  0x20

//
// ME MMIO Regions
//
#define ME_PAVP_BASE      0xFED40000
#define ME_DMA_MMIO_SIZE  0x1000

//
// Host Memory Target
//
#define HOST_KERNEL_TEXT  0xFFFF800000000000ULL

//
// DMA Status Bits
//
#define ME_DMA_COMPLETE  BIT0
#define ME_DMA_ERROR     BIT1

//
// DMA Transfer Limits
//
#define DMA_MAX_TRANSFER  0x1000

//
// DMA Transfer Direction
//
typedef enum {
  DmaHostToMe = 0,
  DmaMeToHost
} ME_DMA_DIRECTION;

//
// DMA Transfer Record
//
typedef struct {
  UINT64             SrcAddr;
  UINT64             DstAddr;
  UINT32             Length;
  ME_DMA_DIRECTION   Direction;
  UINT32             Status;
} ME_DMA_TRANSFER_RECORD;

//
// Module State Machine
//
typedef enum {
  MeDmaStateInit = 0,
  MeDmaStateLocated,
  MeDmaStateMapped,
  MeDmaStateReadComplete,
  MeDmaStateWriteComplete,
  MeDmaStateComplete,
  MeDmaStateError
} ME_DMA_STATE;

//
// Module Context
//
typedef struct {
  BOOLEAN                  Initialized;
  ME_DMA_STATE             State;
  UINT64                   DmaControllerBase;
  UINT64                   UmaBase;
  UINT32                   UmaSize;
  struct {
    ME_DMA_TRANSFER_RECORD Records[4];
    UINT32                 Count;
  }                        HostMemoryReadOps;
  struct {
    ME_DMA_TRANSFER_RECORD Records[4];
    UINT32                 Count;
  }                        HostMemoryWriteOps;
  UINT32                   TotalBytesRead;
  UINT32                   TotalBytesWritten;
} ME_DMA_CONTEXT;

//
// Function Prototypes
//

/**
  Initialize the ME DMA attack context.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS     Context initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeMeDmaAttack (
  IN OUT ME_DMA_CONTEXT  *Context
  );

/**
  Locate the ME PAVP DMA controller.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS     DMA controller located.
**/
EFI_STATUS
EFIAPI
LocateMeDmaEngine (
  IN OUT ME_DMA_CONTEXT  *Context
  );

/**
  Map host physical address space from ME's perspective.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS     Host memory mapped.
**/
EFI_STATUS
EFIAPI
MapHostMemory (
  IN OUT ME_DMA_CONTEXT  *Context
  );

/**
  Simulate DMA reads from host memory.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS     Read operations completed.
**/
EFI_STATUS
EFIAPI
ReadHostMemory (
  IN OUT ME_DMA_CONTEXT  *Context
  );

/**
  Simulate DMA writes to host memory.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS     Write operations completed.
**/
EFI_STATUS
EFIAPI
WriteHostMemory (
  IN OUT ME_DMA_CONTEXT  *Context
  );

/**
  Log final status of ME DMA operations.

  @param[in] Context  Pointer to the module context.
**/
VOID
EFIAPI
LogMeDmaStatus (
  IN ME_DMA_CONTEXT  *Context
  );

/**
  Module entry point.

  @param[in] ImageHandle  Handle of the loaded image.
  @param[in] SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS     Always returns success.
**/
EFI_STATUS
EFIAPI
MeDmaAttackEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

#endif // ME_DMA_ATTACK_H_
