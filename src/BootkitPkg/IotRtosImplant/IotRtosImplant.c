/** @file
  IoT RTOS Implant Persistence Emulation - Implementation

  Emulates RTOS implant persistence on IoT / embedded devices. Models
  FreeRTOS/ThreadX-style task injection into the scheduler task table,
  SVC (supervisor call) hook table redirection, and watchdog-disable
  persistence written to a simulated internal flash page.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  Every table, register, and flash page referenced lives only inside
  this module's own context structure.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "IotRtosImplant.h"

STATIC RTOS_IMPLANT_CONTEXT  gRtosImplantContext;

/**
  Validate kill-switch conditions (time-bomb expiry).

  Returns TRUE if execution should proceed (kill-switch NOT triggered).
**/
STATIC
BOOLEAN
ValidateKillSwitch (
  VOID
  )
{
  EFI_STATUS  Status;
  EFI_TIME    CurrentTime;

  Status = gRT->GetTime (&CurrentTime, NULL);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "GetTime failed: %r - aborting\n", Status));
    return FALSE;
  }

  //
  // Time-bomb: hard stop after the project expiry date
  // (BARZAKH_EXPIRY_DATE default: 2027-05-11).
  //
  if ((CurrentTime.Year > 2027) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month > 5) ||
      (CurrentTime.Year == 2027 && CurrentTime.Month == 5 && CurrentTime.Day > 11))
  {
    DEBUG ((DEBUG_WARN, RTOS_DEBUG_PREFIX "Expiry date reached - aborting\n"));
    return FALSE;
  }

  return TRUE;
}

/**
  Initialize RTOS implant context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeRtosImplant (
  OUT RTOS_IMPLANT_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (RTOS_IMPLANT_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = RtosStateInit;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Target: IoT RTOS implant persistence (FreeRTOS/ThreadX)\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Attack vector: task injection + SVC hooks + WDT disable\n"));

  return EFI_SUCCESS;
}

/**
  Probe the simulated RTOS environment.

  Models the discovery phase of a firmware implant: fingerprinting the
  RTOS (task names, scheduler structures) and locating the task table
  and vector table in the device memory map.
**/
EFI_STATUS
EFIAPI
ProbeRtosEnvironment (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "--- Phase 1: Probe RTOS Environment ---\n"));

  //
  // In a real attack, the RTOS is fingerprinted by scanning flash for
  // version strings and scheduler data structures (pxCurrentTCB on
  // FreeRTOS, _tx_thread_system_state on ThreadX).
  //
  Context->RtosType     = RTOS_TYPE_FREERTOS;
  Context->RtosVersion  = 0x0A0403;   // "V10.4.3"
  Context->TaskTableBase = RTOS_TASK_TABLE_BASE;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] Flash scan: FreeRTOS V10.4.3 signature found\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] pxCurrentTCB @ 0x%lx, uxTopUsedPriority=5\n",
    Context->TaskTableBase));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] Vector table @ 0x%lx, SVCall slot %u -> handler 0x%lx\n",
    RTOS_VECTOR_TABLE, (UINT32)RTOS_SVC_VECTOR_SLOT, RTOS_ORIGINAL_SVC_HANDLER));

  //
  // Seed the emulated task table with the target's genuine tasks.
  //
  Context->Tasks[0].Name       = "IDLE";
  Context->Tasks[0].Priority   = 0;
  Context->Tasks[0].StackSize  = 128;
  Context->Tasks[0].EntryPoint = 0x08002140ULL;
  Context->Tasks[0].Injected   = FALSE;

  Context->Tasks[1].Name       = "Tmr Svc";
  Context->Tasks[1].Priority   = 1;
  Context->Tasks[1].StackSize  = 256;
  Context->Tasks[1].EntryPoint = 0x080023C0ULL;
  Context->Tasks[1].Injected   = FALSE;

  Context->Tasks[2].Name       = "main";
  Context->Tasks[2].Priority   = 2;
  Context->Tasks[2].StackSize  = 1024;
  Context->Tasks[2].EntryPoint = 0x08001520ULL;
  Context->Tasks[2].Injected   = FALSE;

  Context->Tasks[3].Name       = "usbd";
  Context->Tasks[3].Priority   = 3;
  Context->Tasks[3].StackSize  = 512;
  Context->Tasks[3].EntryPoint = 0x080048A0ULL;
  Context->Tasks[3].Injected   = FALSE;

  Context->TaskCount = 4;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Genuine tasks: %u (IDLE, Tmr Svc, main, usbd)\n",
    Context->TaskCount));

  Context->State = RtosStateProbed;
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "State -> Probed\n"));

  return EFI_SUCCESS;
}

/**
  Emulate task injection into the RTOS scheduler.

  Models xTaskCreate()/tx_thread_create() calls issued by the implant,
  including a task masquerading as a second idle task to avoid
  suspicion in task listings.
**/
EFI_STATUS
EFIAPI
InjectRtosTasks (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < RtosStateProbed) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "--- Phase 2: Inject Implant Tasks ---\n"));

  if (Context->TaskCount + 3 > RTOS_MAX_TASKS) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "Task table full - cannot inject\n"));
    Context->State = RtosStateError;
    return EFI_OUT_OF_RESOURCES;
  }

  //
  // Injected task 1: masquerades as a second idle task. Hides in plain
  // sight because most inventory tooling only expects one IDLE entry.
  //
  Idx = Context->TaskCount;
  Context->Tasks[Idx].Name       = "idle2";
  Context->Tasks[Idx].Priority   = 0;
  Context->Tasks[Idx].StackSize  = 256;
  Context->Tasks[Idx].EntryPoint = RTOS_IMPLANT_REGION + 0x0100;
  Context->Tasks[Idx].Injected   = TRUE;
  Context->TaskCount++;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] xTaskCreate(name=%a, prio=%u, stack=%u) -> TCB 0x%lx\n",
    Context->Tasks[Idx].Name, Context->Tasks[Idx].Priority,
    Context->Tasks[Idx].StackSize, Context->Tasks[Idx].EntryPoint));

  //
  // Injected task 2: data monitor with elevated priority so it preempts
  // genuine application tasks (sensor data harvesting model).
  //
  Idx = Context->TaskCount;
  Context->Tasks[Idx].Name       = "dmon";
  Context->Tasks[Idx].Priority   = 4;
  Context->Tasks[Idx].StackSize  = 512;
  Context->Tasks[Idx].EntryPoint = RTOS_IMPLANT_REGION + 0x0200;
  Context->Tasks[Idx].Injected   = TRUE;
  Context->TaskCount++;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] xTaskCreate(name=%a, prio=%u, stack=%u) -> TCB 0x%lx\n",
    Context->Tasks[Idx].Name, Context->Tasks[Idx].Priority,
    Context->Tasks[Idx].StackSize, Context->Tasks[Idx].EntryPoint));

  //
  // Injected task 3: C2 link over the device's telematics interface,
  // running above every genuine task.
  //
  Idx = Context->TaskCount;
  Context->Tasks[Idx].Name       = "c2link";
  Context->Tasks[Idx].Priority   = 5;
  Context->Tasks[Idx].StackSize  = 1024;
  Context->Tasks[Idx].EntryPoint = RTOS_IMPLANT_REGION + 0x0300;
  Context->Tasks[Idx].Injected   = TRUE;
  Context->TaskCount++;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] xTaskCreate(name=%a, prio=%u, stack=%u) -> TCB 0x%lx\n",
    Context->Tasks[Idx].Name, Context->Tasks[Idx].Priority,
    Context->Tasks[Idx].StackSize, Context->Tasks[Idx].EntryPoint));

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Task table now holds %u entries (%u injected)\n",
    Context->TaskCount, (UINT32)3));

  Context->State = RtosStateTasksInjected;
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "State -> TasksInjected\n"));

  return EFI_SUCCESS;
}

/**
  Emulate SVC hook table redirection.

  Models the implant's syscall interception layer: the SVCall exception
  handler is redirected through a hook table so privileged RTOS services
  (queue posts, NVM reads) can be monitored or forged.
**/
EFI_STATUS
EFIAPI
HookSvcTable (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < RtosStateTasksInjected) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "--- Phase 3: Emulate SVC Hook Table ---\n"));

  //
  // In a real attack, the implant either patches the SVCall vector
  // directly or installs a trampoline that dispatches through a hook
  // table before reaching the genuine handler.
  //
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] Vector table write: SVCall[%u] 0x%lx -> 0x%lx\n",
    (UINT32)RTOS_SVC_VECTOR_SLOT, RTOS_ORIGINAL_SVC_HANDLER,
    RTOS_IMPLANT_REGION + 0x0010));

  Context->SvcHooks[0].SyscallNumber  = 0x01;   // task yield
  Context->SvcHooks[0].OriginalHandler = 0x08004A10ULL;
  Context->SvcHooks[0].HookedHandler  = RTOS_IMPLANT_REGION + 0x0020;
  Context->SvcHooks[0].Active         = TRUE;

  Context->SvcHooks[1].SyscallNumber  = 0x04;   // queue post
  Context->SvcHooks[1].OriginalHandler = 0x08003C80ULL;
  Context->SvcHooks[1].HookedHandler  = RTOS_IMPLANT_REGION + 0x0030;
  Context->SvcHooks[1].Active         = TRUE;

  Context->SvcHooks[2].SyscallNumber  = 0x12;   // NVM read (forged data path)
  Context->SvcHooks[2].OriginalHandler = 0x08006B40ULL;
  Context->SvcHooks[2].HookedHandler  = RTOS_IMPLANT_REGION + 0x0040;
  Context->SvcHooks[2].Active         = TRUE;

  Context->SvcHookCount = 3;

  for (Idx = 0; Idx < Context->SvcHookCount; Idx++) {
    DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "  Hook[%u]: syscall=0x%02x 0x%lx -> 0x%lx\n",
      Idx, Context->SvcHooks[Idx].SyscallNumber,
      Context->SvcHooks[Idx].OriginalHandler,
      Context->SvcHooks[Idx].HookedHandler));
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "SVC hook table installed (%u entries, chained to originals)\n",
    Context->SvcHookCount));

  Context->State = RtosStateSvcHooked;
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "State -> SvcHooked\n"));

  return EFI_SUCCESS;
}

/**
  Emulate watchdog disable and persistence.

  Models the last persistence stage: silencing the hardware watchdog so
  a hung implant never triggers a reset, and committing a boot-time
  re-arm record to the (simulated) last flash page so the implant
  re-establishes itself after every reboot.
**/
EFI_STATUS
EFIAPI
DisableWatchdogPersistence (
  IN OUT RTOS_IMPLANT_CONTEXT  *Context
  )
{
  UINT32  Idx;

  if (Context == NULL || Context->State < RtosStateSvcHooked) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "--- Phase 4: Watchdog Disable + Persistence ---\n"));

  //
  // Watchdog disable (logged only): setting the disable bit in the
  // watchdog mode register stops the WDT from resetting the device.
  //
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] WDT_MR write 0x%lx <= 0x00008000 (WDDIS)\n",
    RTOS_WATCHDOG_MR));
  Context->WatchdogDisabled = TRUE;
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Hardware watchdog: DISABLED (emulated)\n"));

  //
  // Persistence record: a 64-byte boot re-arm blob staged in the
  // implant's NVM shadow. In a functional build this is the payload
  // that would be written to the last internal flash page; here it
  // only ever lives in module memory.
  //
  Context->NvShadow[0] = 'B';
  Context->NvShadow[1] = 'Z';
  Context->NvShadow[2] = 'K';
  Context->NvShadow[3] = 'H';
  Context->NvShadow[4] = 0x01;                  // Record version
  Context->NvShadow[5] = 0x03;                  // Task count to re-create
  Context->NvShadow[6] = 0x03;                  // SVC hooks to re-install
  Context->NvShadow[7] = 0x01;                  // WDT disable flag

  for (Idx = 8; Idx < RTOS_NVM_SHADOW_SIZE; Idx++) {
    Context->NvShadow[Idx] = (UINT8)(Idx ^ 0x5A);
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] Would write 64-byte persistence record to flash page 0x%lx\n",
    RTOS_NVM_PAGE));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "[SIM] Record: tasks=3 hooks=3 wdt=off (staged in shadow only)\n"));
  Context->PersistenceInstalled = TRUE;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Persistence: re-arms implant tasks, hooks, and WDT state at boot\n"));

  Context->State = RtosStatePersistent;
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "State -> Persistent\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the RTOS implant emulation.
**/
VOID
EFIAPI
LogRtosImplantStatus (
  IN RTOS_IMPLANT_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;
  UINT32  InjectedTasks;
  UINT32  Idx;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "  IoT RTOS Implant - Final Status\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case RtosStateInit:
      StateStr = "Init";
      break;
    case RtosStateProbed:
      StateStr = "Probed";
      break;
    case RtosStateTasksInjected:
      StateStr = "TasksInjected";
      break;
    case RtosStateSvcHooked:
      StateStr = "SvcHooked";
      break;
    case RtosStatePersistent:
      StateStr = "Persistent";
      break;
    case RtosStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  InjectedTasks = 0;
  for (Idx = 0; Idx < Context->TaskCount; Idx++) {
    if (Context->Tasks[Idx].Injected) {
      InjectedTasks++;
    }
  }

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "State:              %a\n", StateStr));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "RTOS fingerprint:   FreeRTOS V10.4.3\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Task table entries: %u (%u injected)\n",
    Context->TaskCount, InjectedTasks));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "SVC hooks active:   %u\n", Context->SvcHookCount));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Watchdog disabled:  %a\n",
    Context->WatchdogDisabled ? "YES" : "NO"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Persistence:        %a\n",
    Context->PersistenceInstalled ? "INSTALLED" : "NOT INSTALLED"));

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "1. Verify RTOS task tables against a signed golden inventory\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "2. Enable watchdog lock-once (WDT cannot be disabled after boot)\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "3. Secure boot with flash write protection for app pages\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "4. Monitor for unexpected SVC vector table modifications\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "5. Use MPU regions to keep scheduler structures read-only\n"));
}

/**
  Entry point for the IoT RTOS implant persistence emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
IotRtosImplantEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "=== IoT RTOS Implant Persistence Emulation ===\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Module: IotRtosImplant v1.0\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Purpose: Model RTOS task injection, SVC hooks, WDT persistence\n"));
  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  //
  // Kill-switch: refuse to run past the project expiry date.
  //
  if (!ValidateKillSwitch ()) {
    DEBUG ((DEBUG_WARN, RTOS_DEBUG_PREFIX "Kill-switch triggered - aborting\n"));
    return EFI_ABORTED;
  }

  Status = InitializeRtosImplant (&gRtosImplantContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = ProbeRtosEnvironment (&gRtosImplantContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "Failed to probe RTOS: %r\n", Status));
    goto Done;
  }

  Status = InjectRtosTasks (&gRtosImplantContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "Failed to inject tasks: %r\n", Status));
    goto Done;
  }

  Status = HookSvcTable (&gRtosImplantContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "Failed to hook SVC table: %r\n", Status));
    goto Done;
  }

  Status = DisableWatchdogPersistence (&gRtosImplantContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, RTOS_DEBUG_PREFIX "Failed to disable watchdog: %r\n", Status));
    goto Done;
  }

Done:
  LogRtosImplantStatus (&gRtosImplantContext);

  DEBUG ((DEBUG_INFO, RTOS_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
