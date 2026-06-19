"""
Firmware Measurer - Walks firmware image and computes measurements.

Parses FV/FFS structures and computes the digests that a conformant
TPM platform would extend into each PCR during measured boot.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from ..detectors.fv_parser import FirmwareVolumeParser, FirmwareVolume, FirmwareFile
from ..detectors.pcr_replay import PCRReplayEngine, HashAlgorithm
from .measurement_policy import MeasurementPolicy, MeasurementEvent, EventType
from .platform_profiles import PlatformProfile


class FirmwareMeasurer:
    """
    Walks a firmware image and produces the measurement event sequence
    that a TCG-conformant platform would generate during boot.
    """

    def __init__(self, profile: PlatformProfile,
                 hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.profile = profile
        self.policy = profile.policy
        self.hash_algorithm = hash_algorithm
        self._hash_size = {
            HashAlgorithm.SHA1: 20,
            HashAlgorithm.SHA256: 32,
            HashAlgorithm.SHA384: 48,
            HashAlgorithm.SHA512: 64,
        }[hash_algorithm]
        self.fv_parser = FirmwareVolumeParser()

    def _hash(self, data: bytes) -> bytes:
        """Compute hash digest of data using configured algorithm."""
        if self.hash_algorithm == HashAlgorithm.SHA1:
            return hashlib.sha1(data).digest()
        elif self.hash_algorithm == HashAlgorithm.SHA256:
            return hashlib.sha256(data).digest()
        elif self.hash_algorithm == HashAlgorithm.SHA384:
            return hashlib.sha384(data).digest()
        elif self.hash_algorithm == HashAlgorithm.SHA512:
            return hashlib.sha512(data).digest()
        return hashlib.sha256(data).digest()

    def measure_firmware(self, firmware_path: str) -> List[MeasurementEvent]:
        """
        Walk firmware image and produce ordered measurement events.

        Args:
            firmware_path: Path to firmware ROM image

        Returns:
            Ordered list of MeasurementEvents representing the PCR
            extension sequence during measured boot.
        """
        events: List[MeasurementEvent] = []

        firmware = Path(firmware_path)
        if not firmware.exists():
            return events

        with open(firmware, 'rb') as f:
            raw_data = f.read()

        volumes = self.fv_parser.parse(firmware_path)
        if not volumes:
            return events

        # Phase 1: S-CRTM version measurement (PCR[0])
        if self.profile.s_crtm_version:
            version_data = self.profile.s_crtm_version.encode('utf-16-le')
            events.append(MeasurementEvent(
                pcr_index=0,
                event_type=EventType.EV_S_CRTM_VERSION,
                digest=self._hash(version_data),
                description=f'S-CRTM Version: {self.profile.s_crtm_version}',
            ))

        # Phase 2: FV blob measurements and file measurements
        for fv in volumes:
            fv_events = self._measure_firmware_volume(fv, raw_data)
            events.extend(fv_events)

        # Phase 3: Separator events (marks transition from pre-OS to OS)
        if self.policy.measure_separator:
            for pcr_idx in range(8):
                separator_data = b'\x00\x00\x00\x00'
                events.append(MeasurementEvent(
                    pcr_index=pcr_idx,
                    event_type=EventType.EV_SEPARATOR,
                    digest=self._hash(separator_data),
                    description=f'EV_SEPARATOR for PCR[{pcr_idx}]',
                ))

        return events

    def _measure_firmware_volume(self, fv: FirmwareVolume,
                                  raw_data: bytes) -> List[MeasurementEvent]:
        """Measure a single Firmware Volume and its contents."""
        events: List[MeasurementEvent] = []

        # Measure FV as blob first (if policy says so)
        if self.policy.measure_fv_as_blob and self.profile.measures_fv_before_files:
            fv_data = raw_data[fv.offset:fv.offset + fv.size]
            if fv_data:
                events.append(MeasurementEvent(
                    pcr_index=self.policy.fv_blob_pcr,
                    event_type=EventType.EV_EFI_PLATFORM_FIRMWARE_BLOB,
                    digest=self._hash(fv_data),
                    description=f'FV blob at 0x{fv.offset:x} (size={fv.size})',
                    component_guid=fv.guid,
                    component_type='FIRMWARE_VOLUME',
                ))

        # Measure individual files
        for ff in fv.files:
            if not self.policy.should_measure(ff.type, ff.guid):
                continue

            pcr_index = self.policy.get_pcr_for_file_type(ff.type)
            event_type = self.policy.get_event_type_for_file_type(ff.type)
            file_type_name = FirmwareVolumeParser.FILE_TYPES.get(
                ff.type, f'UNKNOWN(0x{ff.type:02x})')

            events.append(MeasurementEvent(
                pcr_index=pcr_index,
                event_type=event_type,
                digest=self._hash(ff.data),
                description=f'{file_type_name} {ff.guid} (size={ff.size})',
                component_guid=ff.guid,
                component_type=file_type_name,
            ))

        # Measure FV as blob after files (AMD-style)
        if self.policy.measure_fv_as_blob and not self.profile.measures_fv_before_files:
            fv_data = raw_data[fv.offset:fv.offset + fv.size]
            if fv_data:
                events.append(MeasurementEvent(
                    pcr_index=self.policy.fv_blob_pcr,
                    event_type=EventType.EV_EFI_PLATFORM_FIRMWARE_BLOB,
                    digest=self._hash(fv_data),
                    description=f'FV blob at 0x{fv.offset:x} (size={fv.size})',
                    component_guid=fv.guid,
                    component_type='FIRMWARE_VOLUME',
                ))

        return events

    def measure_additional_component(self, data: bytes, pcr_index: int,
                                      event_type: EventType,
                                      description: str) -> MeasurementEvent:
        """
        Create a measurement event for an additional component not in FV.

        Useful for measuring Option ROMs, boot loaders, or other
        components loaded at runtime.
        """
        return MeasurementEvent(
            pcr_index=pcr_index,
            event_type=event_type,
            digest=self._hash(data),
            description=description,
        )

    def get_measurement_summary(self, events: List[MeasurementEvent]) -> Dict:
        """Produce a summary of measurement events by PCR."""
        summary: Dict[int, List[Dict]] = {i: [] for i in range(8)}

        for event in events:
            if event.pcr_index < 8:
                summary[event.pcr_index].append({
                    'event_type': event.event_type.name,
                    'description': event.description,
                    'digest': event.digest.hex(),
                    'component_guid': event.component_guid,
                })

        return {
            'profile': self.profile.name,
            'algorithm': self.hash_algorithm.name,
            'events_per_pcr': {k: len(v) for k, v in summary.items()},
            'total_events': len(events),
            'details': summary,
        }
