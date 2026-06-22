/** @file
  ME DMA Attack Emulation - Implementation

  Simulates Intel Management Engine's independent DMA engine accessing
  host memory. The ME has its own DMA controller that can read/write
  host physical memory independently of the host CPU, bypassing OS
  security boundaries.

  All operations are SIMULATED - no actual hardware access occurs.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "MeDmaAttack.h"

//
// Module-level static context
//
STATIC ME_DMA_CONTEXT  gMeDmaContext;

/**
  Initialize the ME DMA attack context.

  Zeroes all fields and marks the context as initialized.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS     Context initialized successfully.
**/
EFI_STATUS
EFIAPI
InitializeMeDmaAttack (
  IN OUT ME_DMA_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (ME_DMA_CONTEXT));
  Context->Initialized = TRUE;
  Context->State = MeDmaStateInit;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));

  return EFI_SUCCESS;
}

/**
  Locate the ME PAVP DMA controller.

  Simulates discovering the ME's DMA controller via PAVP MMIO region
  and reading the UMA base register to determine ME's stolen memory.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS           DMA controller located.
  @retval EFI_NOT_READY         Context not initialized.
**/
EFI_STATUS
EFIAPI
LocateMeDmaEngine (
  IN OUT ME_DMA_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "--- Phase 1: Locate ME DMA Engine ---\n"));

  //
  // Simulate locating ME PAVP DMA controller at known MMIO base
  //
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] Probing ME PAVP region at 0x%08x\n", ME_PAVP_BASE));
  Context->DmaControllerBase = ME_PAVP_BASE;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA controller found at base 0x%lx (size 0x%x)\n",
    Context->DmaControllerBase, ME_DMA_MMIO_SIZE));

  //
  // Simulate reading UMA base register to find ME stolen memory
  //
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] Reading UMA base register at offset 0x%04x\n", ME_UMA_BASE_REG));
  Context->UmaBase = 0x7E000000ULL;
  Context->UmaSize = 0x02000000;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] ME UMA region: base=0x%lx size=0x%x (%d MB)\n",
    Context->UmaBase, Context->UmaSize, Context->UmaSize / (1024 * 1024)));

  Context->State = MeDmaStateLocated;
  return EFI_SUCCESS;
}

/**
  Map host physical address space from ME's perspective.

  Simulates how the ME DMA engine views host physical memory,
  calculating UMA region boundaries and accessible host ranges.

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS           Host memory mapped.
  @retval EFI_NOT_READY         Previous phase not complete.
**/
EFI_STATUS
EFIAPI
MapHostMemory (
  IN OUT ME_DMA_CONTEXT  *Context
  )
{
  UINT64  HostRangeStart;
  UINT64  HostRangeEnd;

  if (Context == NULL || Context->State < MeDmaStateLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "--- Phase 2: Map Host Memory ---\n"));

  //
  // Simulate ME's view of host physical address space
  //
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] Configuring ME DMA ctrl register at offset 0x%02x\n",
    ME_DMA_CTRL_OFFSET));

  //
  // Calculate accessible host memory range (below and above UMA)
  //
  HostRangeStart = 0x0ULL;
  HostRangeEnd = Context->UmaBase;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] Host range below UMA: 0x%lx - 0x%lx\n",
    HostRangeStart, HostRangeEnd));

  HostRangeStart = Context->UmaBase + Context->UmaSize;
  HostRangeEnd = 0x100000000ULL;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] Host range above UMA: 0x%lx - 0x%lx\n",
    HostRangeStart, HostRangeEnd));

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] ME DMA can access full host physical address space\n"));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] UMA boundary validated - DMA engine ready\n"));

  Context->State = MeDmaStateMapped;
  return EFI_SUCCESS;
}

/**
  Simulate DMA reads from host memory.

  Performs two simulated DMA read operations:
  1. Read from kernel .text section (code theft)
  2. Read from credential structures

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS           Read operations completed.
  @retval EFI_NOT_READY         Previous phase not complete.
**/
EFI_STATUS
EFIAPI
ReadHostMemory (
  IN OUT ME_DMA_CONTEXT  *Context
  )
{
  ME_DMA_TRANSFER_RECORD  *Record;

  if (Context == NULL || Context->State < MeDmaStateMapped) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "--- Phase 3: Read Host Memory ---\n"));

  //
  // DMA Read #1: Kernel .text section (code theft)
  //
  Record = &Context->HostMemoryReadOps.Records[0];
  Record->SrcAddr = HOST_KERNEL_TEXT;
  Record->DstAddr = Context->UmaBase + 0x1000;
  Record->Length = DMA_MAX_TRANSFER;
  Record->Direction = DmaHostToMe;
  Record->Status = ME_DMA_COMPLETE;
  Context->HostMemoryReadOps.Count = 1;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA Read #1: kernel .text theft\n"));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   src=0x%lx (host) -> dst=0x%lx (ME UMA)\n",
    Record->SrcAddr, Record->DstAddr));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   length=0x%x, status=0x%x (complete)\n",
    Record->Length, Record->Status));

  Context->TotalBytesRead += Record->Length;

  //
  // DMA Read #2: Credential structures
  //
  Record = &Context->HostMemoryReadOps.Records[1];
  Record->SrcAddr = HOST_KERNEL_TEXT + 0x800000;
  Record->DstAddr = Context->UmaBase + 0x2000;
  Record->Length = 0x800;
  Record->Direction = DmaHostToMe;
  Record->Status = ME_DMA_COMPLETE;
  Context->HostMemoryReadOps.Count = 2;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA Read #2: credential structures\n"));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   src=0x%lx (host) -> dst=0x%lx (ME UMA)\n",
    Record->SrcAddr, Record->DstAddr));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   length=0x%x, status=0x%x (complete)\n",
    Record->Length, Record->Status));

  Context->TotalBytesRead += Record->Length;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA status register: 0x%02x at offset 0x%02x\n",
    ME_DMA_COMPLETE, ME_DMA_STATUS_OFFSET));

  Context->State = MeDmaStateReadComplete;
  return EFI_SUCCESS;
}

/**
  Simulate DMA writes to host memory.

  Performs two simulated DMA write operations:
  1. Inject shellcode at page-aligned boundary
  2. Modify kernel data structures

  @param[in,out] Context  Pointer to the module context.

  @retval EFI_SUCCESS           Write operations completed.
  @retval EFI_NOT_READY         Previous phase not complete.
**/
EFI_STATUS
EFIAPI
WriteHostMemory (
  IN OUT ME_DMA_CONTEXT  *Context
  )
{
  ME_DMA_TRANSFER_RECORD  *Record;

  if (Context == NULL || Context->State < MeDmaStateReadComplete) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "--- Phase 4: Write Host Memory ---\n"));

  //
  // DMA Write #1: Inject shellcode at page boundary
  //
  Record = &Context->HostMemoryWriteOps.Records[0];
  Record->SrcAddr = Context->UmaBase + 0x3000;
  Record->DstAddr = HOST_KERNEL_TEXT + 0x200000;
  Record->Length = 0x400;
  Record->Direction = DmaMeToHost;
  Record->Status = ME_DMA_COMPLETE;
  Context->HostMemoryWriteOps.Count = 1;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA Write #1: shellcode injection at page boundary\n"));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   src=0x%lx (ME UMA) -> dst=0x%lx (host)\n",
    Record->SrcAddr, Record->DstAddr));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   length=0x%x, status=0x%x (complete)\n",
    Record->Length, Record->Status));

  Context->TotalBytesWritten += Record->Length;

  //
  // DMA Write #2: Modify kernel data structures
  //
  Record = &Context->HostMemoryWriteOps.Records[1];
  Record->SrcAddr = Context->UmaBase + 0x3400;
  Record->DstAddr = HOST_KERNEL_TEXT + 0xA00000;
  Record->Length = 0x200;
  Record->Direction = DmaMeToHost;
  Record->Status = ME_DMA_COMPLETE;
  Context->HostMemoryWriteOps.Count = 2;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA Write #2: kernel data modification\n"));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   src=0x%lx (ME UMA) -> dst=0x%lx (host)\n",
    Record->SrcAddr, Record->DstAddr));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM]   length=0x%x, status=0x%x (complete)\n",
    Record->Length, Record->Status));

  Context->TotalBytesWritten += Record->Length;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "[SIM] DMA status register: 0x%02x at offset 0x%02x\n",
    ME_DMA_COMPLETE, ME_DMA_STATUS_OFFSET));

  Context->State = MeDmaStateWriteComplete;
  return EFI_SUCCESS;
}

/**
  Log final status of ME DMA operations.

  Reports total bytes read and written, number of operations,
  and final module state.

  @param[in] Context  Pointer to the module context.
**/
VOID
EFIAPI
LogMeDmaStatus (
  IN ME_DMA_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "Cannot log status: NULL context\n"));
    return;
  }

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "--- ME DMA Attack Status ---\n"));

  switch (Context->State) {
    case MeDmaStateInit:
      StateStr = "Init";
      break;
    case MeDmaStateLocated:
      StateStr = "Located";
      break;
    case MeDmaStateMapped:
      StateStr = "Mapped";
      break;
    case MeDmaStateReadComplete:
      StateStr = "ReadComplete";
      break;
    case MeDmaStateWriteComplete:
      StateStr = "WriteComplete";
      break;
    case MeDmaStateComplete:
      StateStr = "Complete";
      break;
    case MeDmaStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  State:          %a\n", StateStr));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  DMA Base:       0x%lx\n", Context->DmaControllerBase));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  UMA Base:       0x%lx (size=0x%x)\n",
    Context->UmaBase, Context->UmaSize));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  Read ops:       %d (total %d bytes)\n",
    Context->HostMemoryReadOps.Count, Context->TotalBytesRead));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  Write ops:      %d (total %d bytes)\n",
    Context->HostMemoryWriteOps.Count, Context->TotalBytesWritten));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  Total DMA I/O:  %d bytes\n",
    Context->TotalBytesRead + Context->TotalBytesWritten));

  if (Context->State == MeDmaStateWriteComplete) {
    Context->State = MeDmaStateComplete;
    DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  Result:         ALL PHASES COMPLETE (simulated)\n"));
  } else if (Context->State == MeDmaStateError) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "  Result:         ERROR during execution\n"));
  } else {
    DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "  Result:         PARTIAL (stopped at %a)\n", StateStr));
  }
}

/**
  Module entry point for MeDmaAttack DXE driver.

  Executes all phases sequentially, logs final status,
  and always returns EFI_SUCCESS.

  @param[in] ImageHandle  Handle of the loaded image.
  @param[in] SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS     Always returns success.
**/
EFI_STATUS
EFIAPI
MeDmaAttackEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "=== ME DMA Attack Emulation Starting ===\n"));
  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "SIMULATION_MODE=%d - No real hardware access\n", SIMULATION_MODE));

  Status = InitializeMeDmaAttack (&gMeDmaContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "Failed to initialize context: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateMeDmaEngine (&gMeDmaContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "Failed to locate ME DMA engine: %r\n", Status));
    goto Done;
  }

  Status = MapHostMemory (&gMeDmaContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "Failed to map host memory: %r\n", Status));
    goto Done;
  }

  Status = ReadHostMemory (&gMeDmaContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "Failed to read host memory: %r\n", Status));
    goto Done;
  }

  Status = WriteHostMemory (&gMeDmaContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MEDMA_DEBUG_PREFIX "Failed to write host memory: %r\n", Status));
    goto Done;
  }

Done:
  LogMeDmaStatus (&gMeDmaContext);

  DEBUG ((DEBUG_INFO, MEDMA_DEBUG_PREFIX "=== ME DMA Attack Emulation Complete ===\n"));
  return EFI_SUCCESS;
}
