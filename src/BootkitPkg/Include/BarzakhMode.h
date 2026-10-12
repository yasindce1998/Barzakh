/** @file
  Barzakh build mode control

  Single source of truth for the simulation/functional switch.

  SIMULATION build (default, and the only mode CI builds):
    All hardware-modifying operations are logged and skipped. Nothing
    outside the module's own memory is ever changed. This is what the
    QEMU e2e tests and public artifacts run.

  FUNCTIONAL build (-D BARZAKH_FUNCTIONAL):
    Real hardware paths execute: flash writes through FVB2, real PCI
    enumeration, real MSR writes. Lab-only, behind the kill-switches.
    Building this mode requires an explicit opt-in:

      build ... -D BARZAKH_FUNCTIONAL=1

    A functional build refuses to compile unless BARZAKH_RESEARCH is
    also defined (the project's research-use gate) and prints a
    prominent warning at boot.

  Copyright (c) 2026, Barzakh Research Project
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef __BARZAKH_MODE_H__
#define __BARZAKH_MODE_H__

//
// BARZAKH_FUNCTIONAL is injected by the build system (DSC BuildOptions
// or the -D flag). Do not define it in source files.
//
#ifdef BARZAKH_FUNCTIONAL

//
// Functional builds are research builds by definition.
//
#if !defined (BARZAKH_RESEARCH)
  #error "BARZAKH_FUNCTIONAL requires BARZAKH_RESEARCH (research-use gate)"
#endif

#define BARZAKH_SIMULATION_MODE  FALSE

#else

//
// Default: simulation. Everything hardware-touching is emulated.
//
#define BARZAKH_SIMULATION_MODE  TRUE

#endif

//
// Legacy per-module names kept for source compatibility during the
// transition. New code must use BARZAKH_SIMULATION_MODE.
//
#define SIMULATION_MODE  BARZAKH_SIMULATION_MODE

#endif // __BARZAKH_MODE_H__
