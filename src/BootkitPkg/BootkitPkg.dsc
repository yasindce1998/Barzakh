## @file
# Barzakh Bootkit Package
#
# This package contains the UEFI bootkit emulation modules for academic
# research purposes. All modules include hardware-rooted kill-switches
# and are designed for defensive security research only.
#
# Copyright (c) 2026, Barzakh Research Project
# SPDX-License-Identifier: BSD-2-Clause-Patent
##

[Defines]
  PLATFORM_NAME                  = BootkitPkg
  PLATFORM_GUID                  = 12345678-1234-1234-1234-123456789ABC
  PLATFORM_VERSION               = 1.0
  DSC_SPECIFICATION              = 0x00010005
  OUTPUT_DIRECTORY               = Build/BootkitPkg
  SUPPORTED_ARCHITECTURES        = X64
  BUILD_TARGETS                  = DEBUG|RELEASE
  SKUID_IDENTIFIER               = DEFAULT

[LibraryClasses]
  #
  # Entry point
  #
  UefiDriverEntryPoint|MdePkg/Library/UefiDriverEntryPoint/UefiDriverEntryPoint.inf
  
  #
  # Common Libraries
  #
  BaseLib|MdePkg/Library/BaseLib/BaseLib.inf
  BaseMemoryLib|MdePkg/Library/BaseMemoryLibRepStr/BaseMemoryLibRepStr.inf
  UefiLib|MdePkg/Library/UefiLib/UefiLib.inf
  UefiBootServicesTableLib|MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib.inf
  UefiRuntimeServicesTableLib|MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib.inf
  DevicePathLib|MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib.inf
  MemoryAllocationLib|MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib.inf
  PcdLib|MdePkg/Library/BasePcdLibNull/BasePcdLibNull.inf
  
  #
  # Debug and Print
  #
  DebugLib|MdePkg/Library/BaseDebugLibSerialPort/BaseDebugLibSerialPort.inf
  DebugPrintErrorLevelLib|MdePkg/Library/BaseDebugPrintErrorLevelLib/BaseDebugPrintErrorLevelLib.inf
  PrintLib|MdePkg/Library/BasePrintLib/BasePrintLib.inf
  SerialPortLib|PcAtChipsetPkg/Library/SerialIoLib/SerialIoLib.inf
  
  #
  # Synchronization and Timing
  #
  SynchronizationLib|MdePkg/Library/BaseSynchronizationLib/BaseSynchronizationLib.inf
  TimerLib|MdePkg/Library/BaseTimerLibNullTemplate/BaseTimerLibNullTemplate.inf
  RngLib|MdePkg/Library/BaseRngLibTimerLib/BaseRngLibTimerLib.inf

  #
  # IO and PCI
  #
  IoLib|MdePkg/Library/BaseIoLibIntrinsic/BaseIoLibIntrinsic.inf
  RegisterFilterLib|MdePkg/Library/RegisterFilterLibNull/RegisterFilterLibNull.inf
  PciCf8Lib|MdePkg/Library/BasePciCf8Lib/BasePciCf8Lib.inf
  PciLib|MdePkg/Library/BasePciLibCf8/BasePciLibCf8.inf

  #
  # Security Libraries
  #
  BaseCryptLib|CryptoPkg/Library/BaseCryptLib/BaseCryptLib.inf
  IntrinsicLib|CryptoPkg/Library/IntrinsicLib/IntrinsicLib.inf
  OpensslLib|CryptoPkg/Library/OpensslLib/OpensslLib.inf

  #
  # TPM Libraries
  #
  Tpm2CommandLib|SecurityPkg/Library/Tpm2CommandLib/Tpm2CommandLib.inf
  Tpm2DeviceLib|SecurityPkg/Library/Tpm2DeviceLibDTpm/Tpm2DeviceLibDTpm.inf

[LibraryClasses.common.DXE_DRIVER]
  HobLib|MdePkg/Library/DxeHobLib/DxeHobLib.inf

[PcdsFixedAtBuild]
  # Debug output level
  gEfiMdePkgTokenSpaceGuid.PcdDebugPropertyMask|0x2F
  gEfiMdePkgTokenSpaceGuid.PcdDebugPrintErrorLevel|0x80000047
  
  # Serial port configuration
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultBaudRate|115200
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultDataBits|8
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultParity|1
  gEfiMdePkgTokenSpaceGuid.PcdUartDefaultStopBits|1

[Components]
  #
  # DXE Injection Module
  #
  BootkitPkg/DxeInject/DxeInject.inf
  
  #
  # ExitBootServices Hook Module
  #
  BootkitPkg/ExitBootHook/ExitBootHook.inf

  #
  # Adversarial Firmware Emulation Modules
  #
  BootkitPkg/SmmPersistence/SmmPersistence.inf
  BootkitPkg/SpiChipsetEmulator/SpiChipsetEmulator.inf
  BootkitPkg/CapsuleHijack/CapsuleHijack.inf
  BootkitPkg/AcpiTableInject/AcpiTableInject.inf
  BootkitPkg/VirtualAddressMapHook/VirtualAddressMapHook.inf
  BootkitPkg/PciOptionRom/PciOptionRom.inf

  #
  # Ring -3 (Intel ME / AMD PSP) Emulation Modules
  #
  BootkitPkg/HeciIntercept/HeciIntercept.inf
  BootkitPkg/MeSpiManipulation/MeSpiManipulation.inf
  BootkitPkg/AmtSolChannel/AmtSolChannel.inf
  BootkitPkg/FtpmCommandForge/FtpmCommandForge.inf
  BootkitPkg/MeDmaAttack/MeDmaAttack.inf

[BuildOptions]
  # Enable security features
  GCC:*_*_*_CC_FLAGS = -DBARZAKH_RESEARCH=1
  
  # Reproducible builds
  GCC:*_*_*_CC_FLAGS = -frandom-seed=barzakh-$(SOURCE_DATE_EPOCH)
  
  # Security hardening (no stack protector — UEFI has no __stack_chk_fail runtime)
  GCC:*_*_*_CC_FLAGS = -fno-stack-protector
  
  # Warning flags (no -Wextra: conflicts with EDK2 library code patterns)
  GCC:*_*_*_CC_FLAGS = -Wall -Wno-unused-parameter -Werror=implicit-function-declaration