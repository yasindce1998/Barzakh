/** @file
  ME SPI Manipulation Emulation - Implementation

  Emulates direct manipulation of the Intel Management Engine (ME) region
  within the SPI flash descriptor. Models SPI controller discovery via PCH
  RCBA, flash descriptor parsing, ME region boundary extraction, and
  partition table modification to extend the ME region.

  SIMULATION ONLY - All hardware operations are logged, never executed.
  This module serves as a research reference for defensive security teams
  studying Intel ME SPI flash attack vectors.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "MeSpiManipulation.h"

STATIC ME_SPI_CONTEXT  gMeSpiContext;

/**
  Initialize ME SPI manipulation context to clean state.
**/
EFI_STATUS
EFIAPI
InitializeMeSpiManipulation (
  OUT ME_SPI_CONTEXT  *Context
  )
{
  if (Context == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Context, sizeof (ME_SPI_CONTEXT));
  Context->Initialized = TRUE;
  Context->State       = MeSpiStateInit;

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Context initialized (SIMULATION_MODE=%d)\n", SIMULATION_MODE));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Target: Intel ME region within SPI flash descriptor\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Attack vector: Direct SPI flash descriptor manipulation\n"));

  return EFI_SUCCESS;
}

/**
  Locate the SPI controller via PCH RCBA (Root Complex Base Address).

  On Intel platforms, the SPI controller is accessed through the SPIBAR
  register within the PCH RCBA MMIO space. The SPIBAR provides access to
  flash descriptor registers, region access control, and write/erase
  operations.
**/
EFI_STATUS
EFIAPI
LocateSpiController (
  IN OUT ME_SPI_CONTEXT  *Context
  )
{
  if (Context == NULL || !Context->Initialized) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "--- Phase 1: Locate SPI Controller ---\n"));

  //
  // In a real attack, the SPI controller is located via:
  // 1. Reading PCH RCBA from PCI config space (D31:F0 offset F0h)
  // 2. Adding SPIBAR offset (0x3800) to RCBA base
  // 3. Accessing SPI registers through the resulting MMIO address
  //
  Context->SpiBarBase = PCH_RCBA_BASE + SPIBAR_OFFSET;

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "PCH RCBA base:    0x%08x\n", PCH_RCBA_BASE));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "SPIBAR offset:    0x%04x\n", SPIBAR_OFFSET));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "SPIBAR address:   0x%lx\n", Context->SpiBarBase));

  //
  // Simulate reading SPI controller identification
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Reading SPI controller ID at SPIBAR+0x00\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] SPI controller detected: Intel PCH SPI (100-series)\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] HSFS register (SPIBAR+0x04): hardware sequencing enabled\n"));

  Context->State = MeSpiStateLocated;
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "State -> Located\n"));

  return EFI_SUCCESS;
}

/**
  Read and parse the 4KB SPI flash descriptor.

  The flash descriptor is the first 4KB of SPI flash and contains:
  - Signature (0x0FF0A55A at offset 0x10)
  - Flash map registers (FLMAP0, FLMAP1, FLMAP2)
  - Region definitions (BIOS, ME, GbE, Platform Data)
  - Master access permissions
**/
EFI_STATUS
EFIAPI
ReadFlashDescriptor (
  IN OUT ME_SPI_CONTEXT  *Context
  )
{
  UINT32  Signature;
  UINT32  FlReg1Value;
  UINT32  MeBase;
  UINT32  MeLimit;

  if (Context == NULL || Context->State < MeSpiStateLocated) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "--- Phase 2: Read Flash Descriptor ---\n"));

  //
  // Simulate reading the 4KB flash descriptor from SPI flash offset 0x0
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Issuing SPI read cycle: address=0x000000 length=4096\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Setting FADDR register to 0x00000000\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Setting FDBC (byte count) to 64 (max per cycle)\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Triggering read via HSFC.FGO bit\n"));

  //
  // Simulate flash descriptor contents
  //
  ZeroMem (Context->FlashDescriptor, sizeof (Context->FlashDescriptor));

  //
  // Place signature at expected offset (0x10 in descriptor)
  //
  Signature = SPI_FLASH_DESCRIPTOR_SIG;
  CopyMem (&Context->FlashDescriptor[0x10], &Signature, sizeof (UINT32));

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Flash descriptor signature: 0x%08x (VALID)\n", Signature));

  //
  // Simulate FLMAP0 and FLMAP1 values
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] FLMAP0 (offset 0x%02x): 0x00040003\n", FLMAP0_OFFSET));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] FLMAP1 (offset 0x%02x): 0x12100206\n", FLMAP1_OFFSET));

  //
  // Parse ME region boundaries from FLREG1
  // FLREG format: [31:16]=Region Limit, [15:0]=Region Base (in 4KB units)
  //
  MeBase  = 0x00003000;   // ME starts at 3MB (0x3000 * 4KB = 0x3000000... simplified)
  MeLimit = 0x00180000;   // ME ends at base + ME_REGION_SIZE

  FlReg1Value = ((MeLimit >> 12) << 16) | (MeBase >> 12);
  CopyMem (&Context->FlashDescriptor[FLREG1_ME_OFFSET], &FlReg1Value, sizeof (UINT32));

  Context->MeRegion.OrigBase  = MeBase;
  Context->MeRegion.OrigLimit = MeLimit;

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "--- Flash Region Map ---\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  FLREG0 (BIOS): offset 0x%02x\n", FLREG0_BIOS_OFFSET));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  FLREG1 (ME):   offset 0x%02x -> Base=0x%06x Limit=0x%06x\n",
    FLREG1_ME_OFFSET, MeBase, MeLimit));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  FLREG2 (GbE):  offset 0x%02x\n", FLREG2_GBE_OFFSET));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  ME region size: 0x%x (%u KB)\n",
    ME_REGION_SIZE, ME_REGION_SIZE / 1024));

  Context->State = MeSpiStateDescriptorRead;
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "State -> DescriptorRead\n"));

  return EFI_SUCCESS;
}

/**
  Modify the ME region boundaries in the flash descriptor.

  Extends the ME region limit to consume adjacent free space, effectively
  expanding the ME partition. Also simulates writing modified partition
  table entries and checking the FLOCKDN (Flash Lock-Down) bit which
  prevents descriptor writes on production systems.
**/
EFI_STATUS
EFIAPI
ModifyMeRegion (
  IN OUT ME_SPI_CONTEXT  *Context
  )
{
  UINT32  NewLimit;
  UINT32  ModifiedFlReg1;

  if (Context == NULL || Context->State < MeSpiStateDescriptorRead) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "--- Phase 3: Modify ME Region ---\n"));

  //
  // Check FLOCKDN bit - on production systems this prevents descriptor writes
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Reading HSFS register for FLOCKDN status\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] HSFS.FLOCKDN (bit 15): "));

  //
  // Simulate FLOCKDN as cleared (vulnerable configuration)
  //
  Context->FlockdnStatus = FALSE;
  DEBUG ((DEBUG_INFO, "CLEAR (descriptor writable!)\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  WARNING: Flash descriptor is not locked down\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  This indicates a vulnerable BIOS configuration\n"));

  //
  // Extend ME region limit by 256KB
  //
  NewLimit = Context->MeRegion.OrigLimit + 0x40000;
  Context->MeRegion.ModifiedBase  = Context->MeRegion.OrigBase;
  Context->MeRegion.ModifiedLimit = NewLimit;

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Modifying ME region boundaries:\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  Original:  Base=0x%06x Limit=0x%06x (size=0x%x)\n",
    Context->MeRegion.OrigBase, Context->MeRegion.OrigLimit,
    Context->MeRegion.OrigLimit - Context->MeRegion.OrigBase));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  Modified:  Base=0x%06x Limit=0x%06x (size=0x%x)\n",
    Context->MeRegion.ModifiedBase, Context->MeRegion.ModifiedLimit,
    Context->MeRegion.ModifiedLimit - Context->MeRegion.ModifiedBase));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  Extension: +0x40000 (256 KB)\n"));

  //
  // Write modified FLREG1 value back to descriptor buffer
  //
  ModifiedFlReg1 = ((NewLimit >> 12) << 16) | (Context->MeRegion.ModifiedBase >> 12);
  CopyMem (&Context->FlashDescriptor[FLREG1_ME_OFFSET], &ModifiedFlReg1, sizeof (UINT32));

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Writing modified FLREG1: 0x%08x\n", ModifiedFlReg1));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Partition table entry updated in descriptor buffer\n"));

  Context->WriteAttempts++;

  Context->State = MeSpiStateModified;
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "State -> Modified\n"));

  return EFI_SUCCESS;
}

/**
  Persist the modified flash descriptor back to SPI flash.

  Simulates the SPI write cycle to commit the modified ME region
  boundaries. Logs the write operation results including cycle
  timing and verification status.
**/
EFI_STATUS
EFIAPI
PersistMeSpiModification (
  IN OUT ME_SPI_CONTEXT  *Context
  )
{
  if (Context == NULL || Context->State < MeSpiStateModified) {
    return EFI_NOT_READY;
  }

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "--- Phase 4: Persist Modification ---\n"));

  //
  // Simulate SPI write cycle to flash descriptor region
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Preparing SPI write cycle to descriptor region\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Setting FADDR to 0x00000000 (descriptor base)\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Loading FDATA registers with modified descriptor\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Setting HSFC: cycle=WRITE, FDBC=63, FGO=1\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Waiting for HSFS.FDONE...\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] HSFS.FDONE set - write cycle complete\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] HSFS.FCERR: 0 (no errors)\n"));

  Context->SuccessfulWrites++;

  //
  // Simulate verification read-back
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] Verification: re-reading descriptor from SPI flash\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] FLREG1 readback matches expected value\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "[SIM] ME region modification persisted successfully\n"));

  Context->State = MeSpiStateComplete;
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "State -> Complete\n"));

  return EFI_SUCCESS;
}

/**
  Log final status of the ME SPI manipulation emulation.
**/
VOID
EFIAPI
LogMeSpiStatus (
  IN ME_SPI_CONTEXT  *Context
  )
{
  CHAR8  *StateStr;

  if (Context == NULL) {
    return;
  }

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "  ME SPI Manipulation - Final Status\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "========================================\n"));

  switch (Context->State) {
    case MeSpiStateInit:
      StateStr = "Init";
      break;
    case MeSpiStateLocated:
      StateStr = "Located";
      break;
    case MeSpiStateDescriptorRead:
      StateStr = "DescriptorRead";
      break;
    case MeSpiStateModified:
      StateStr = "Modified";
      break;
    case MeSpiStateComplete:
      StateStr = "Complete";
      break;
    case MeSpiStateError:
      StateStr = "Error";
      break;
    default:
      StateStr = "Unknown";
      break;
  }

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "State:             %a\n", StateStr));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "SPIBAR base:       0x%lx\n", Context->SpiBarBase));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "FLOCKDN locked:    %a\n",
    Context->FlockdnStatus ? "YES" : "NO"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "ME region orig:    0x%06x - 0x%06x\n",
    Context->MeRegion.OrigBase, Context->MeRegion.OrigLimit));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "ME region modified:0x%06x - 0x%06x\n",
    Context->MeRegion.ModifiedBase, Context->MeRegion.ModifiedLimit));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Write attempts:    %u\n", Context->WriteAttempts));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Successful writes: %u\n", Context->SuccessfulWrites));

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "========================================\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "SIMULATION COMPLETE - No hardware modified\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "========================================\n"));

  //
  // Defensive notes for blue team:
  //
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "--- Defensive Mitigations ---\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "1. FLOCKDN bit must be set by BIOS before OS handoff\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "2. Intel Boot Guard verifies descriptor integrity on boot\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "3. SPI Protected Range registers (PRx) lock ME region\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "4. SMM-based SPI write protection (BIOS_CNTL.SMM_BWP)\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "5. Intel CSME update mechanisms detect tampered regions\n"));
}

/**
  Entry point for the ME SPI Manipulation emulation module.

  @param[in]  ImageHandle  Handle for this driver image.
  @param[in]  SystemTable  Pointer to the EFI System Table.

  @retval EFI_SUCCESS  Module executed successfully (simulation complete).
**/
EFI_STATUS
EFIAPI
MeSpiManipulationEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS  Status;

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "=== Intel ME SPI Flash Manipulation Emulation ===\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Module: MeSpiManipulation v1.0\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Purpose: Model ME region descriptor manipulation\n"));
  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Mode: SIMULATION ONLY (BARZAKH_RESEARCH)\n\n"));

  Status = InitializeMeSpiManipulation (&gMeSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MESPI_DEBUG_PREFIX "Failed to initialize: %r\n", Status));
    return EFI_SUCCESS;
  }

  Status = LocateSpiController (&gMeSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MESPI_DEBUG_PREFIX "Failed to locate SPI controller: %r\n", Status));
    goto Done;
  }

  Status = ReadFlashDescriptor (&gMeSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MESPI_DEBUG_PREFIX "Failed to read flash descriptor: %r\n", Status));
    goto Done;
  }

  Status = ModifyMeRegion (&gMeSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MESPI_DEBUG_PREFIX "Failed to modify ME region: %r\n", Status));
    goto Done;
  }

  Status = PersistMeSpiModification (&gMeSpiContext);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, MESPI_DEBUG_PREFIX "Failed to persist modification: %r\n", Status));
    goto Done;
  }

Done:
  LogMeSpiStatus (&gMeSpiContext);

  DEBUG ((DEBUG_INFO, MESPI_DEBUG_PREFIX "Module unloading (research emulation complete)\n"));
  return EFI_SUCCESS;
}
