"""
Measurement Policy - Platform-specific PCR measurement rules.

Defines which firmware components get measured into which PCRs,
following TCG PC Client Platform Firmware Profile Specification.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class EventType(IntEnum):
    """TCG Event Log event types (subset relevant to firmware)."""
    EV_POST_CODE = 0x00000001
    EV_NO_ACTION = 0x00000003
    EV_SEPARATOR = 0x00000004
    EV_ACTION = 0x00000005
    EV_EVENT_TAG = 0x00000006
    EV_S_CRTM_CONTENTS = 0x00000007
    EV_S_CRTM_VERSION = 0x00000008
    EV_CPU_MICROCODE = 0x00000009
    EV_PLATFORM_CONFIG_FLAGS = 0x0000000A
    EV_TABLE_OF_DEVICES = 0x0000000B
    EV_COMPACT_HASH = 0x0000000C
    EV_NONHOST_CODE = 0x0000000F
    EV_NONHOST_CONFIG = 0x00000010
    EV_NONHOST_INFO = 0x00000011
    EV_EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
    EV_EFI_VARIABLE_BOOT = 0x80000002
    EV_EFI_BOOT_SERVICES_APPLICATION = 0x80000003
    EV_EFI_BOOT_SERVICES_DRIVER = 0x80000004
    EV_EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
    EV_EFI_GPT_EVENT = 0x80000006
    EV_EFI_ACTION = 0x80000007
    EV_EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008
    EV_EFI_HANDOFF_TABLES = 0x80000009
    EV_EFI_VARIABLE_AUTHORITY = 0x800000E0


@dataclass
class MeasurementEvent:
    """A single measurement event to be extended into a PCR."""
    pcr_index: int
    event_type: EventType
    digest: bytes
    description: str
    component_guid: Optional[str] = None
    component_type: Optional[str] = None


@dataclass
class MeasurementPolicy:
    """
    Defines how a platform measures firmware components into PCRs.

    Based on TCG PC Client Platform Firmware Profile Specification 1.06:
    - PCR[0]: S-CRTM, BIOS/UEFI code, embedded option ROMs
    - PCR[1]: Host platform configuration (CPU microcode, platform config)
    - PCR[2]: Option ROM code
    - PCR[3]: Option ROM configuration and data
    - PCR[4]: IPL code (boot loaders, OS loaders)
    - PCR[5]: IPL configuration and data (boot device config)
    - PCR[6]: Host platform manufacturer specific
    - PCR[7]: Secure Boot policy
    """
    name: str
    description: str

    measure_pei_core: bool = True
    measure_dxe_core: bool = True
    measure_dxe_drivers: bool = True
    measure_peim: bool = True
    measure_fv_as_blob: bool = True
    measure_secure_boot_vars: bool = True
    measure_separator: bool = True

    fv_blob_pcr: int = 0
    pei_core_pcr: int = 0
    dxe_core_pcr: int = 0
    dxe_driver_pcr: int = 0
    peim_pcr: int = 0
    secure_boot_pcr: int = 7
    boot_app_pcr: int = 4

    file_type_pcr_map: Dict[int, int] = field(default_factory=lambda: {
        0x03: 0,   # SECURITY_CORE -> PCR[0]
        0x04: 0,   # PEI_CORE -> PCR[0]
        0x05: 0,   # DXE_CORE -> PCR[0]
        0x06: 0,   # PEIM -> PCR[0]
        0x07: 0,   # DRIVER -> PCR[0]
        0x08: 0,   # COMBINED_PEIM_DRIVER -> PCR[0]
        0x09: 4,   # APPLICATION -> PCR[4]
        0x0A: 0,   # MM -> PCR[0]
        0x0B: 0,   # FIRMWARE_VOLUME_IMAGE -> PCR[0]
        0x0C: 0,   # COMBINED_MM_DXE -> PCR[0]
        0x0D: 0,   # MM_CORE -> PCR[0]
        0x0E: 0,   # MM_STANDALONE -> PCR[0]
        0x0F: 0,   # MM_CORE_STANDALONE -> PCR[0]
    })

    excluded_guids: List[str] = field(default_factory=list)

    def get_pcr_for_file_type(self, file_type: int) -> int:
        """Get target PCR index for a given FFS file type."""
        return self.file_type_pcr_map.get(file_type, self.dxe_driver_pcr)

    def get_event_type_for_file_type(self, file_type: int) -> EventType:
        """Get TCG event type for a given FFS file type."""
        if file_type == 0x09:
            return EventType.EV_EFI_BOOT_SERVICES_APPLICATION
        elif file_type in (0x07, 0x08, 0x0C):
            return EventType.EV_EFI_BOOT_SERVICES_DRIVER
        elif file_type in (0x0A, 0x0D, 0x0E, 0x0F):
            return EventType.EV_EFI_RUNTIME_SERVICES_DRIVER
        elif file_type == 0x0B:
            return EventType.EV_EFI_PLATFORM_FIRMWARE_BLOB
        else:
            return EventType.EV_EFI_PLATFORM_FIRMWARE_BLOB

    def should_measure(self, file_type: int, guid: str) -> bool:
        """Determine if a firmware file should be measured."""
        if guid in self.excluded_guids:
            return False
        if file_type == 0x04 and not self.measure_pei_core:
            return False
        if file_type == 0x05 and not self.measure_dxe_core:
            return False
        if file_type == 0x07 and not self.measure_dxe_drivers:
            return False
        if file_type == 0x06 and not self.measure_peim:
            return False
        return True
