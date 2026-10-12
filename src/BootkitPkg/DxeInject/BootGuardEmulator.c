/** @file
  Boot Guard Emulator - Implementation

  Models Intel Boot Guard / AMD PSB Initial Boot Block measurement
  and verification. Identifies the DXE FV attack surface that
  remains outside hardware-measured regions.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "BootGuardEmulator.h"
#include <BarzakhMode.h>

STATIC CHAR8  *mProfileNames[] = {
  "Disabled",
  "Measured Boot",
  "Verified Boot",
  "Measured + Verified"
};

/**
  Simple SHA-256-style hash accumulator (simulation).

  Real Boot Guard uses SHA-256/SHA-384. We simulate with a
  simple XOR-fold for demonstration since we don't link a
  full crypto library in this emulation context.
**/
STATIC
VOID
SimulateHash256 (
  IN  UINT8   *Data,
  IN  UINT32  Size,
  OUT UINT8   *Digest
  )
{
  UINT32  Index;

  SetMem (Digest, 32, 0);

  for (Index = 0; Index < Size; Index++) {
    Digest[Index % 32] ^= Data[Index];
  }
}

EFI_STATUS
EFIAPI
InitializeBootGuardEmulator (
  IN OUT BOOT_GUARD_EMULATOR  *Emulator,
  IN     BOOT_GUARD_PROFILE   Profile
  )
{
  if (Emulator == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (Profile > BootGuardMeasuredVerified) {
    return EFI_INVALID_PARAMETER;
  }

  ZeroMem (Emulator, sizeof (BOOT_GUARD_EMULATOR));

  Emulator->Profile                = Profile;
  Emulator->AcmStatus             = ACM_STATUS_VALID;
  Emulator->IbbSegmentCount       = 0;
  Emulator->IbbMeasurementComplete = FALSE;
  Emulator->KeyManifestRevision   = 1;
  Emulator->EnforcementOnFailure  = (Profile == BootGuardVerifiedBoot ||
                                     Profile == BootGuardMeasuredVerified);
  Emulator->NonMeasuredRegionFound = FALSE;
  Emulator->Initialized           = TRUE;

  DEBUG ((
    DEBUG_INFO,
    "[BootGuard-Emu] Initialized — Profile: %a, Enforcement: %a\n",
    mProfileNames[Profile],
    Emulator->EnforcementOnFailure ? "SHUTDOWN" : "CONTINUE"
    ));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
BootGuardAddIbbSegment (
  IN BOOT_GUARD_EMULATOR  *Emulator,
  IN UINT32               Base,
  IN UINT32               Size
  )
{
  IBB_SEGMENT  *Segment;

  if (Emulator == NULL || !Emulator->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  if (Emulator->IbbSegmentCount >= IBB_MAX_SEGMENTS) {
    DEBUG ((DEBUG_ERROR, "[BootGuard-Emu] Max IBB segments reached\n"));
    return EFI_OUT_OF_RESOURCES;
  }

  Segment = &Emulator->IbbSegments[Emulator->IbbSegmentCount];
  Segment->Base = Base;
  Segment->Size = Size;
  ZeroMem (Segment->Hash, 32);

  Emulator->IbbSegmentCount++;

  DEBUG ((
    DEBUG_INFO,
    "[BootGuard-Emu] IBB segment %d: Base=0x%x Size=0x%x\n",
    Emulator->IbbSegmentCount - 1,
    Base,
    Size
    ));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
EmulateIbbMeasurement (
  IN BOOT_GUARD_EMULATOR  *Emulator,
  IN UINT8                *FlashData,
  IN UINT32               FlashSize
  )
{
  UINT32       Index;
  IBB_SEGMENT  *Segment;
  UINT8        CombinedDigest[32];

  if (Emulator == NULL || !Emulator->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  if (FlashData == NULL || FlashSize == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (Emulator->IbbSegmentCount == 0) {
    DEBUG ((DEBUG_WARN, "[BootGuard-Emu] No IBB segments configured\n"));
    return EFI_NOT_READY;
  }

  if (Emulator->Profile == BootGuardDisabled) {
    DEBUG ((DEBUG_INFO, "[BootGuard-Emu] Profile disabled — skipping measurement\n"));
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu] === IBB Measurement Start ===\n"));

  SetMem (CombinedDigest, 32, 0);

  for (Index = 0; Index < Emulator->IbbSegmentCount; Index++) {
    Segment = &Emulator->IbbSegments[Index];

    if (Segment->Base + Segment->Size > FlashSize) {
      DEBUG ((
        DEBUG_ERROR,
        "[BootGuard-Emu] Segment %d exceeds flash bounds\n",
        Index
        ));
      Emulator->AcmStatus |= ACM_STATUS_STARTUP_ERROR;
      return EFI_DEVICE_ERROR;
    }

    SimulateHash256 (
      FlashData + Segment->Base,
      Segment->Size,
      Segment->Hash
      );

    // Accumulate into combined digest
    SimulateHash256 (Segment->Hash, 32, CombinedDigest);

    DEBUG ((
      DEBUG_INFO,
      "[BootGuard-Emu] Segment %d measured: Base=0x%x Size=0x%x\n",
      Index,
      Segment->Base,
      Segment->Size
      ));
  }

  CopyMem (Emulator->IbbDigest, CombinedDigest, 32);
  Emulator->IbbMeasurementComplete = TRUE;
  Emulator->AcmStatus |= ACM_STATUS_IBB_MEASURED;

  if (Emulator->Profile == BootGuardVerifiedBoot ||
      Emulator->Profile == BootGuardMeasuredVerified) {
    Emulator->AcmStatus |= ACM_STATUS_IBB_VERIFIED;
    DEBUG ((DEBUG_INFO, "[BootGuard-Emu] IBB signature verification: SIMULATED PASS\n"));
  }

  DEBUG ((DEBUG_INFO, "[BootGuard-Emu] PCR[%d] extended with IBB digest\n", BOOT_GUARD_PCR_IBB));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu] PCR[%d] extended with authority\n", BOOT_GUARD_PCR_AUTHORITY));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu] === IBB Measurement Complete ===\n\n"));

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
FindNonMeasuredPersistenceSlot (
  IN  BOOT_GUARD_EMULATOR  *Emulator,
  IN  UINT32               FvBase,
  IN  UINT32               FvSize,
  OUT UINT32               *SlotBase,
  OUT UINT32               *SlotSize
  )
{
  UINT32       Index;
  IBB_SEGMENT  *Segment;
  UINT32       MeasuredEnd;
  UINT32       FvEnd;

  if (Emulator == NULL || !Emulator->Initialized) {
    return EFI_INVALID_PARAMETER;
  }

  if (SlotBase == NULL || SlotSize == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (!Emulator->IbbMeasurementComplete) {
    DEBUG ((DEBUG_WARN, "[BootGuard-Emu] Cannot find slots before measurement\n"));
    return EFI_NOT_READY;
  }

  //
  // Boot Guard typically measures SEC + PEI (IBB) but NOT the DXE FV.
  // Find the end of the last measured segment that overlaps with the FV,
  // then everything after that in the FV is unmeasured — the attack surface.
  //
  MeasuredEnd = 0;
  FvEnd = FvBase + FvSize;

  for (Index = 0; Index < Emulator->IbbSegmentCount; Index++) {
    Segment = &Emulator->IbbSegments[Index];
    UINT32 SegEnd = Segment->Base + Segment->Size;

    if (SegEnd > MeasuredEnd && Segment->Base < FvEnd) {
      MeasuredEnd = SegEnd;
    }
  }

  //
  // If measured region doesn't cover the entire FV, the remainder is a slot
  //
  if (MeasuredEnd < FvEnd && MeasuredEnd >= FvBase) {
    *SlotBase = MeasuredEnd;
    *SlotSize = FvEnd - MeasuredEnd;
  } else if (MeasuredEnd <= FvBase) {
    // Entire FV is unmeasured
    *SlotBase = FvBase;
    *SlotSize = FvSize;
  } else {
    // FV is entirely within measured region
    *SlotBase = 0;
    *SlotSize = 0;
    Emulator->NonMeasuredRegionFound = FALSE;
    DEBUG ((DEBUG_INFO, "[BootGuard-Emu] FV entirely within IBB — no unmeasured slots\n"));
    return EFI_NOT_FOUND;
  }

  Emulator->NonMeasuredBase = *SlotBase;
  Emulator->NonMeasuredSize = *SlotSize;
  Emulator->NonMeasuredRegionFound = TRUE;

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu] *** NON-MEASURED PERSISTENCE SLOT ***\n"));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu]   Base: 0x%08x\n", *SlotBase));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu]   Size: 0x%x (%d KB)\n", *SlotSize, *SlotSize / 1024));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu]   Attack: MosaicRegressor / CosmicStrand inject here\n"));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu]   Reason: Boot Guard ACM only measures IBB (SEC+PEI)\n\n"));

  return EFI_SUCCESS;
}

VOID
EFIAPI
LogBootGuardStatus (
  IN BOOT_GUARD_EMULATOR  *Emulator
  )
{
  UINT32  Index;

  if (Emulator == NULL || !Emulator->Initialized) {
    return;
  }

  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "[BootGuard-Emu] Status Report\n"));
  DEBUG ((DEBUG_INFO, "========================================\n"));
  DEBUG ((DEBUG_INFO, "  Profile:     %a\n", mProfileNames[Emulator->Profile]));
  DEBUG ((DEBUG_INFO, "  ACM Status:  0x%08x\n", Emulator->AcmStatus));
  DEBUG ((DEBUG_INFO, "  Enforcement: %a\n",
    Emulator->EnforcementOnFailure ? "Shutdown on failure" : "Continue on failure"));
  DEBUG ((DEBUG_INFO, "  KM Revision: %d\n", Emulator->KeyManifestRevision));
  DEBUG ((DEBUG_INFO, "\n"));
  DEBUG ((DEBUG_INFO, "  IBB Segments: %d\n", Emulator->IbbSegmentCount));

  for (Index = 0; Index < Emulator->IbbSegmentCount; Index++) {
    DEBUG ((
      DEBUG_INFO,
      "    [%d] Base=0x%08x Size=0x%x Measured=%a\n",
      Index,
      Emulator->IbbSegments[Index].Base,
      Emulator->IbbSegments[Index].Size,
      Emulator->IbbMeasurementComplete ? "YES" : "NO"
      ));
  }

  if (Emulator->NonMeasuredRegionFound) {
    DEBUG ((DEBUG_INFO, "\n"));
    DEBUG ((DEBUG_INFO, "  *** NON-MEASURED REGION ***\n"));
    DEBUG ((DEBUG_INFO, "    Base: 0x%08x  Size: 0x%x\n",
      Emulator->NonMeasuredBase, Emulator->NonMeasuredSize));
  }

  DEBUG ((DEBUG_INFO, "========================================\n\n"));
}
