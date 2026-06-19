"""
PCR Oracle - Top-level API for TPM PCR prediction.

Predicts final PCR[0-7] values for a firmware image by simulating
the measured boot process using platform-specific measurement policies.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from ..detectors.pcr_replay import PCRReplayEngine, HashAlgorithm
from .firmware_measurer import FirmwareMeasurer
from .measurement_policy import MeasurementEvent
from .platform_profiles import PlatformProfile, get_profile


class PCROracle:
    """
    TPM PCR Prediction Oracle.

    Statically predicts PCR[0-7] values for any firmware image
    without requiring real TPM hardware. Uses platform-specific
    measurement policies to simulate the exact extension sequence.
    """

    def __init__(self, profile: Optional[PlatformProfile] = None,
                 profile_name: Optional[str] = None,
                 hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        """
        Initialize PCR Oracle.

        Args:
            profile: PlatformProfile instance (takes precedence)
            profile_name: Profile name string (used if profile is None)
            hash_algorithm: Hash algorithm for PCR computation
        """
        if profile is not None:
            self.profile = profile
        elif profile_name is not None:
            self.profile = get_profile(profile_name)
        else:
            self.profile = get_profile('generic')

        self.hash_algorithm = hash_algorithm
        self.measurer = FirmwareMeasurer(self.profile, hash_algorithm)
        self.replay_engine = PCRReplayEngine(hash_algorithm)
        self._last_events: List[MeasurementEvent] = []

    def predict(self, firmware_path: str) -> Dict[int, bytes]:
        """
        Predict PCR[0-7] values for a firmware image.

        Args:
            firmware_path: Path to firmware ROM image

        Returns:
            Dictionary mapping PCR index (0-7) to predicted value (bytes)
        """
        self.replay_engine.reset()
        self._last_events = self.measurer.measure_firmware(firmware_path)

        for event in self._last_events:
            if 0 <= event.pcr_index < 8:
                self.replay_engine.extend_pcr(event.pcr_index, event.digest)

        return {i: self.replay_engine.get_pcr_value(i) for i in range(8)}

    def predict_and_compare(self, firmware_path: str,
                            actual_pcrs: Dict[int, bytes]) -> List[Dict]:
        """
        Predict PCRs and compare against actual TPM values.

        Args:
            firmware_path: Path to firmware ROM
            actual_pcrs: Actual PCR values from TPM (index -> bytes)

        Returns:
            List of findings for mismatched PCRs
        """
        predicted = self.predict(firmware_path)
        findings = []

        for pcr_idx in range(8):
            predicted_val = predicted.get(pcr_idx, b'\x00' * 32)
            actual_val = actual_pcrs.get(pcr_idx)

            if actual_val is None:
                continue

            if predicted_val != actual_val:
                findings.append({
                    'detector': 'pcr_oracle',
                    'severity': 'critical',
                    'title': f'PCR[{pcr_idx}] prediction mismatch',
                    'description': (
                        f'Predicted PCR[{pcr_idx}] does not match actual TPM value. '
                        f'This indicates unmeasured firmware modifications — '
                        f'a bootkit may have injected code after measurement.'
                    ),
                    'details': {
                        'pcr_index': pcr_idx,
                        'predicted': predicted_val.hex(),
                        'actual': actual_val.hex(),
                        'algorithm': self.hash_algorithm.name,
                        'profile': self.profile.name,
                        'extension_count': self.replay_engine.get_extension_count(pcr_idx),
                    },
                    'confidence': 0.95,
                    'recommendation': (
                        'Compare event logs. Firmware image may have been modified '
                        'after TPM measurements were taken, or a bootkit injected '
                        'a DXE driver that is not in the measurement policy.'
                    ),
                })

        return findings

    def get_event_log(self) -> List[Dict]:
        """
        Get the simulated event log from the last prediction.

        Returns:
            List of event dictionaries matching TCG event log format
        """
        return [
            {
                'pcr_index': event.pcr_index,
                'event_type': event.event_type.value,
                'event_type_name': event.event_type.name,
                'digests': [{
                    'algorithm': self.hash_algorithm.value,
                    'algorithm_name': self.hash_algorithm.name,
                    'digest': event.digest.hex(),
                }],
                'description': event.description,
                'component_guid': event.component_guid,
                'component_type': event.component_type,
            }
            for event in self._last_events
        ]

    def get_measurement_summary(self) -> Dict:
        """Get summary statistics from last prediction."""
        return self.measurer.get_measurement_summary(self._last_events)

    def export_predicted_state(self, output_path: str):
        """
        Export predicted PCR state and event log to JSON file.

        Args:
            output_path: Path for output JSON file
        """
        state = {
            'profile': self.profile.name,
            'vendor': self.profile.vendor,
            'algorithm': self.hash_algorithm.name,
            'predicted_pcrs': {
                str(i): self.replay_engine.get_pcr_value(i).hex()
                for i in range(8)
            },
            'event_log': self.get_event_log(),
            'summary': self.get_measurement_summary(),
        }

        with open(output_path, 'w') as f:
            json.dump(state, f, indent=2)

    def detect(self, target_path: str) -> List[Dict]:
        """
        Scanner-compatible detect interface.

        Runs prediction and reports findings about the firmware image
        (anomalies like empty PCRs when measurements expected, etc.)
        """
        findings = []
        predicted = self.predict(target_path)

        hash_size = self.replay_engine.hash_size
        zero_pcr = b'\x00' * hash_size

        for pcr_idx in range(8):
            ext_count = self.replay_engine.get_extension_count(pcr_idx)
            if ext_count == 0 and pcr_idx in (0, 2, 4, 7):
                findings.append({
                    'detector': 'pcr_oracle',
                    'severity': 'medium',
                    'title': f'PCR[{pcr_idx}] has no measurements',
                    'description': (
                        f'No firmware components were measured into PCR[{pcr_idx}]. '
                        f'This may indicate missing firmware volumes or an '
                        f'incomplete firmware image.'
                    ),
                    'details': {
                        'pcr_index': pcr_idx,
                        'extension_count': 0,
                        'profile': self.profile.name,
                    },
                    'confidence': 0.6,
                    'recommendation': 'Verify firmware image completeness.',
                })

        return findings


def predict_pcrs(firmware_path: str,
                 profile_name: str = 'generic',
                 hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256
                 ) -> Dict[int, bytes]:
    """
    Convenience function: predict PCR values for a firmware image.

    Args:
        firmware_path: Path to firmware ROM image
        profile_name: Platform profile name
        hash_algorithm: Hash algorithm to use

    Returns:
        Dictionary mapping PCR index to predicted value
    """
    oracle = PCROracle(profile_name=profile_name, hash_algorithm=hash_algorithm)
    return oracle.predict(firmware_path)
