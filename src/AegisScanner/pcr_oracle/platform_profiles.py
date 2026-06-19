"""
Platform Profiles - Known platform measurement behaviors.

Different firmware implementations (OVMF, Intel, AMD) measure
components in different orders and with different policies.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from .measurement_policy import MeasurementPolicy


@dataclass
class PlatformProfile:
    """Complete platform measurement profile."""
    name: str
    vendor: str
    description: str
    policy: MeasurementPolicy
    initial_pcr_values: Dict[int, bytes] = field(default_factory=dict)
    s_crtm_version: Optional[str] = None
    measures_fv_before_files: bool = True
    measures_separator_after_pei: bool = True


OVMF_PROFILE = PlatformProfile(
    name='ovmf',
    vendor='TianoCore',
    description='OVMF (Open Virtual Machine Firmware) for QEMU/KVM',
    policy=MeasurementPolicy(
        name='ovmf_default',
        description='OVMF default measurement policy',
        measure_pei_core=True,
        measure_dxe_core=True,
        measure_dxe_drivers=True,
        measure_peim=True,
        measure_fv_as_blob=True,
        measure_secure_boot_vars=True,
        measure_separator=True,
        fv_blob_pcr=0,
        pei_core_pcr=0,
        dxe_core_pcr=0,
        dxe_driver_pcr=0,
        peim_pcr=0,
        secure_boot_pcr=7,
        boot_app_pcr=4,
    ),
    s_crtm_version='edk2-stable202405',
    measures_fv_before_files=True,
    measures_separator_after_pei=True,
)

INTEL_WHISKEY_LAKE_PROFILE = PlatformProfile(
    name='intel_whl',
    vendor='Intel',
    description='Intel Whiskey Lake (8th Gen) platform firmware',
    policy=MeasurementPolicy(
        name='intel_whl_policy',
        description='Intel Whiskey Lake measurement policy',
        measure_pei_core=True,
        measure_dxe_core=True,
        measure_dxe_drivers=True,
        measure_peim=True,
        measure_fv_as_blob=True,
        measure_secure_boot_vars=True,
        measure_separator=True,
        fv_blob_pcr=0,
        pei_core_pcr=0,
        dxe_core_pcr=0,
        dxe_driver_pcr=0,
        peim_pcr=0,
        secure_boot_pcr=7,
        boot_app_pcr=4,
        excluded_guids=[
            '1b45cc0a-156a-428a-af62-49864da0e6e6',  # Intel ME Update
        ],
    ),
    s_crtm_version='Intel_WHL_BIOS_v1.0',
    measures_fv_before_files=True,
    measures_separator_after_pei=True,
)

AMD_RENOIR_PROFILE = PlatformProfile(
    name='amd_renoir',
    vendor='AMD',
    description='AMD Renoir (Ryzen 4000) platform firmware',
    policy=MeasurementPolicy(
        name='amd_renoir_policy',
        description='AMD Renoir measurement policy',
        measure_pei_core=True,
        measure_dxe_core=True,
        measure_dxe_drivers=True,
        measure_peim=True,
        measure_fv_as_blob=True,
        measure_secure_boot_vars=True,
        measure_separator=True,
        fv_blob_pcr=0,
        pei_core_pcr=0,
        dxe_core_pcr=0,
        dxe_driver_pcr=0,
        peim_pcr=0,
        secure_boot_pcr=7,
        boot_app_pcr=4,
        excluded_guids=[
            'be3df093-4b0b-4b3b-a7f0-2a36bfbc4e07',  # AMD PSP FW
        ],
    ),
    s_crtm_version='AMD_Renoir_AGESA_1.0',
    measures_fv_before_files=False,
    measures_separator_after_pei=True,
)

GENERIC_PROFILE = PlatformProfile(
    name='generic',
    vendor='Generic',
    description='Generic UEFI platform (conservative measurement assumptions)',
    policy=MeasurementPolicy(
        name='generic_policy',
        description='Generic TCG-conformant measurement policy',
        measure_pei_core=True,
        measure_dxe_core=True,
        measure_dxe_drivers=True,
        measure_peim=True,
        measure_fv_as_blob=True,
        measure_secure_boot_vars=True,
        measure_separator=True,
    ),
    measures_fv_before_files=True,
    measures_separator_after_pei=True,
)

_PROFILES: Dict[str, PlatformProfile] = {
    'ovmf': OVMF_PROFILE,
    'intel_whl': INTEL_WHISKEY_LAKE_PROFILE,
    'amd_renoir': AMD_RENOIR_PROFILE,
    'generic': GENERIC_PROFILE,
}


def get_profile(name: str) -> PlatformProfile:
    """
    Get a platform profile by name.

    Args:
        name: Profile name (ovmf, intel_whl, amd_renoir, generic)

    Returns:
        PlatformProfile instance

    Raises:
        ValueError: If profile name is unknown
    """
    if name not in _PROFILES:
        available = ', '.join(_PROFILES.keys())
        raise ValueError(f"Unknown profile '{name}'. Available: {available}")
    return _PROFILES[name]


def list_profiles() -> List[str]:
    """Return list of available profile names."""
    return list(_PROFILES.keys())


def register_profile(profile: PlatformProfile):
    """Register a custom platform profile."""
    _PROFILES[profile.name] = profile
