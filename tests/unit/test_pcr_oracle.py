"""
Unit tests for PCR Prediction Oracle.

Tests the full prediction pipeline: measurement policy,
firmware measurer, platform profiles, and oracle API.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import hashlib
import os
import struct
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from AegisScanner.pcr_oracle.measurement_policy import (
    MeasurementPolicy, MeasurementEvent, EventType
)
from AegisScanner.pcr_oracle.platform_profiles import (
    PlatformProfile, get_profile, list_profiles, register_profile,
    OVMF_PROFILE, GENERIC_PROFILE
)
from AegisScanner.pcr_oracle.firmware_measurer import FirmwareMeasurer
from AegisScanner.pcr_oracle.oracle import PCROracle, predict_pcrs
from AegisScanner.detectors.pcr_replay import PCRReplayEngine, HashAlgorithm


class TestMeasurementPolicy:
    """Test MeasurementPolicy class."""

    def test_default_policy(self):
        policy = MeasurementPolicy(name='test', description='test policy')
        assert policy.fv_blob_pcr == 0
        assert policy.secure_boot_pcr == 7
        assert policy.boot_app_pcr == 4

    def test_pcr_for_file_type(self):
        policy = MeasurementPolicy(name='test', description='test')
        assert policy.get_pcr_for_file_type(0x07) == 0  # DRIVER -> PCR[0]
        assert policy.get_pcr_for_file_type(0x09) == 4  # APPLICATION -> PCR[4]
        assert policy.get_pcr_for_file_type(0x04) == 0  # PEI_CORE -> PCR[0]

    def test_event_type_for_file_type(self):
        policy = MeasurementPolicy(name='test', description='test')
        assert policy.get_event_type_for_file_type(0x09) == EventType.EV_EFI_BOOT_SERVICES_APPLICATION
        assert policy.get_event_type_for_file_type(0x07) == EventType.EV_EFI_BOOT_SERVICES_DRIVER
        assert policy.get_event_type_for_file_type(0x0A) == EventType.EV_EFI_RUNTIME_SERVICES_DRIVER

    def test_should_measure_excludes_guids(self):
        policy = MeasurementPolicy(
            name='test', description='test',
            excluded_guids=['deadbeef-1234-5678-9abc-def012345678']
        )
        assert not policy.should_measure(0x07, 'deadbeef-1234-5678-9abc-def012345678')
        assert policy.should_measure(0x07, 'aabbccdd-1234-5678-9abc-def012345678')

    def test_should_measure_respects_flags(self):
        policy = MeasurementPolicy(
            name='test', description='test',
            measure_dxe_drivers=False
        )
        assert not policy.should_measure(0x07, 'some-guid')
        assert policy.should_measure(0x09, 'some-guid')  # APPLICATION still measured


class TestPlatformProfiles:
    """Test platform profiles."""

    def test_get_ovmf_profile(self):
        profile = get_profile('ovmf')
        assert profile.name == 'ovmf'
        assert profile.vendor == 'TianoCore'
        assert profile.s_crtm_version == 'edk2-stable202405'

    def test_get_generic_profile(self):
        profile = get_profile('generic')
        assert profile.name == 'generic'
        assert profile.policy.measure_fv_as_blob is True

    def test_list_profiles(self):
        profiles = list_profiles()
        assert 'ovmf' in profiles
        assert 'generic' in profiles
        assert 'intel_whl' in profiles
        assert 'amd_renoir' in profiles

    def test_unknown_profile_raises(self):
        with pytest.raises(ValueError, match="Unknown profile"):
            get_profile('nonexistent')

    def test_register_custom_profile(self):
        custom = PlatformProfile(
            name='custom_test',
            vendor='Test',
            description='Custom test profile',
            policy=MeasurementPolicy(name='custom', description='custom')
        )
        register_profile(custom)
        retrieved = get_profile('custom_test')
        assert retrieved.vendor == 'Test'

    def test_amd_measures_fv_after_files(self):
        profile = get_profile('amd_renoir')
        assert profile.measures_fv_before_files is False


class TestPCROracle:
    """Test the PCR Oracle prediction engine."""

    def test_oracle_init_default(self):
        oracle = PCROracle()
        assert oracle.profile.name == 'generic'
        assert oracle.hash_algorithm == HashAlgorithm.SHA256

    def test_oracle_init_with_profile_name(self):
        oracle = PCROracle(profile_name='ovmf')
        assert oracle.profile.name == 'ovmf'

    def test_oracle_init_with_profile_object(self):
        oracle = PCROracle(profile=OVMF_PROFILE)
        assert oracle.profile.vendor == 'TianoCore'

    def test_predict_empty_file(self):
        """Predicting on an empty/nonexistent file returns all-zero PCRs."""
        oracle = PCROracle(profile_name='generic')
        result = oracle.predict('/nonexistent/path.rom')
        for i in range(8):
            assert result[i] == b'\x00' * 32

    def test_predict_returns_8_pcrs(self):
        oracle = PCROracle()
        result = oracle.predict('/nonexistent/path.rom')
        assert len(result) == 8
        for i in range(8):
            assert i in result
            assert len(result[i]) == 32

    def test_predict_and_compare_mismatch(self):
        """When actual PCRs differ from predicted, findings are generated."""
        oracle = PCROracle()
        oracle.predict('/nonexistent/path.rom')

        actual = {0: b'\xff' * 32, 1: b'\x00' * 32}
        findings = oracle.predict_and_compare('/nonexistent/path.rom', actual)

        pcr0_findings = [f for f in findings if f['details']['pcr_index'] == 0]
        assert len(pcr0_findings) == 1
        assert pcr0_findings[0]['severity'] == 'critical'

    def test_predict_and_compare_match(self):
        """When actual PCRs match predicted, no findings are generated."""
        oracle = PCROracle()
        predicted = oracle.predict('/nonexistent/path.rom')
        findings = oracle.predict_and_compare('/nonexistent/path.rom', predicted)
        assert len(findings) == 0

    def test_get_event_log_empty(self):
        oracle = PCROracle()
        oracle.predict('/nonexistent/path.rom')
        log = oracle.get_event_log()
        assert isinstance(log, list)

    def test_detect_interface(self):
        """Oracle implements scanner-compatible detect() interface."""
        oracle = PCROracle()
        findings = oracle.detect('/nonexistent/path.rom')
        assert isinstance(findings, list)

    def test_export_predicted_state(self):
        oracle = PCROracle(profile_name='ovmf')
        oracle.predict('/nonexistent/path.rom')

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            oracle.export_predicted_state(output_path)
            import json
            with open(output_path) as f:
                state = json.load(f)
            assert state['profile'] == 'ovmf'
            assert state['algorithm'] == 'SHA256'
            assert 'predicted_pcrs' in state
            assert '0' in state['predicted_pcrs']
        finally:
            os.unlink(output_path)


class TestFirmwareMeasurer:
    """Test the firmware measurement engine."""

    def test_measurer_init(self):
        measurer = FirmwareMeasurer(OVMF_PROFILE)
        assert measurer.hash_algorithm == HashAlgorithm.SHA256

    def test_measure_nonexistent_file(self):
        measurer = FirmwareMeasurer(GENERIC_PROFILE)
        events = measurer.measure_firmware('/nonexistent/path.rom')
        assert events == []

    def test_measure_additional_component(self):
        measurer = FirmwareMeasurer(GENERIC_PROFILE)
        data = b'test component data'
        event = measurer.measure_additional_component(
            data, pcr_index=2,
            event_type=EventType.EV_EFI_BOOT_SERVICES_DRIVER,
            description='Test driver'
        )
        assert event.pcr_index == 2
        assert event.digest == hashlib.sha256(data).digest()
        assert event.description == 'Test driver'

    def test_measurement_summary(self):
        measurer = FirmwareMeasurer(GENERIC_PROFILE)
        events = [
            MeasurementEvent(
                pcr_index=0,
                event_type=EventType.EV_S_CRTM_VERSION,
                digest=b'\x00' * 32,
                description='test'
            ),
            MeasurementEvent(
                pcr_index=0,
                event_type=EventType.EV_EFI_PLATFORM_FIRMWARE_BLOB,
                digest=b'\x01' * 32,
                description='blob'
            ),
        ]
        summary = measurer.get_measurement_summary(events)
        assert summary['total_events'] == 2
        assert summary['events_per_pcr'][0] == 2


class TestConvenienceFunction:
    """Test the predict_pcrs convenience function."""

    def test_predict_pcrs_returns_dict(self):
        result = predict_pcrs('/nonexistent/path.rom')
        assert isinstance(result, dict)
        assert len(result) == 8

    def test_predict_pcrs_with_profile(self):
        result = predict_pcrs('/nonexistent/path.rom', profile_name='ovmf')
        assert isinstance(result, dict)


class TestPCRExtensionIntegration:
    """Integration tests verifying PCR extension math is correct."""

    def test_single_extension_matches_manual(self):
        """Verify oracle PCR extension matches manual computation."""
        engine = PCRReplayEngine(HashAlgorithm.SHA256)
        digest = hashlib.sha256(b'test data').digest()
        engine.extend_pcr(0, digest)

        expected = hashlib.sha256(b'\x00' * 32 + digest).digest()
        assert engine.get_pcr_value(0) == expected

    def test_chained_extensions(self):
        """Verify chained extensions produce correct result."""
        engine = PCRReplayEngine(HashAlgorithm.SHA256)
        d1 = hashlib.sha256(b'first').digest()
        d2 = hashlib.sha256(b'second').digest()

        engine.extend_pcr(0, d1)
        engine.extend_pcr(0, d2)

        step1 = hashlib.sha256(b'\x00' * 32 + d1).digest()
        expected = hashlib.sha256(step1 + d2).digest()
        assert engine.get_pcr_value(0) == expected

    def test_sha384_extension(self):
        """Verify SHA-384 PCR extension works."""
        engine = PCRReplayEngine(HashAlgorithm.SHA384)
        digest = hashlib.sha384(b'test').digest()
        engine.extend_pcr(0, digest)

        expected = hashlib.sha384(b'\x00' * 48 + digest).digest()
        assert engine.get_pcr_value(0) == expected


class TestOracleWithSyntheticFirmware:
    """Test oracle against a synthetic firmware image with known structure."""

    def _create_synthetic_firmware(self, tmp_path):
        """
        Create a minimal synthetic firmware image with valid FV header.
        This won't parse as a real FV (parser requires exact structure),
        but tests the oracle's graceful handling.
        """
        fw_path = tmp_path / 'synthetic.rom'
        data = bytearray(64 * 1024)  # 64KB

        # Write FV header at offset 0
        # Zero vector (16 bytes)
        # Filesystem GUID (16 bytes) - use EFI_FIRMWARE_FILE_SYSTEM2_GUID
        fs_guid = bytes.fromhex('78E58C8C 3D8A 1C4F 9935 896185C32DD3'.replace(' ', ''))
        data[16:32] = fs_guid
        # FV length (8 bytes, little-endian)
        struct.pack_into('<Q', data, 32, 64 * 1024)
        # Signature '_FVH' at offset 40
        data[40:44] = b'_FVH'
        # Attributes (4 bytes)
        struct.pack_into('<I', data, 44, 0x0004FEFF)
        # Header length (2 bytes) - 56 bytes
        struct.pack_into('<H', data, 48, 56)
        # Checksum (2 bytes) - skip for testing
        # Revision (1 byte)
        data[55] = 0x02

        fw_path.write_bytes(bytes(data))
        return str(fw_path)

    def test_oracle_with_synthetic_firmware(self, tmp_path):
        """Oracle should handle synthetic firmware without crashing."""
        fw_path = self._create_synthetic_firmware(tmp_path)
        oracle = PCROracle(profile_name='ovmf')
        result = oracle.predict(fw_path)

        assert len(result) == 8
        for i in range(8):
            assert len(result[i]) == 32

    def test_detect_on_synthetic_firmware(self, tmp_path):
        """detect() should run without errors on synthetic firmware."""
        fw_path = self._create_synthetic_firmware(tmp_path)
        oracle = PCROracle(profile_name='generic')
        findings = oracle.detect(fw_path)
        assert isinstance(findings, list)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
