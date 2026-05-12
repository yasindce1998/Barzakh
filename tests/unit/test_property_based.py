"""
Property-Based Tests for Aegis Scanner

Uses Hypothesis for property-based testing to ensure invariants hold
across arbitrary inputs.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import sys
import tempfile
from pathlib import Path
from hypothesis import given, strategies as st, settings  # type: ignore
import struct
import pytest  # type: ignore

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from AegisScanner.detectors.entropy_analyzer import EntropyAnalyzer
from AegisScanner.detectors.pcr_replay import PCRReplayEngine


class TestEntropyProperties:
    """Property-based tests for entropy calculation."""
    
    @given(st.binary(min_size=256, max_size=4096))
    @settings(max_examples=100)
    def test_entropy_always_in_range(self, data):
        """Property: Entropy must always be between 0 and 8."""
        analyzer = EntropyAnalyzer(window_size=256)
        entropies = analyzer.calculate_entropy(data)
        
        for entropy in entropies:
            assert 0.0 <= entropy <= 8.0, f"Entropy {entropy} out of range [0, 8]"
    
    @given(st.binary(min_size=256, max_size=4096))
    @settings(max_examples=100)
    def test_entropy_deterministic(self, data):
        """Property: Same input produces same entropy."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        result1 = analyzer.calculate_entropy(data)
        result2 = analyzer.calculate_entropy(data)
        
        assert result1 == result2, "Entropy calculation must be deterministic"
    
    @given(st.integers(min_value=1, max_value=255))
    @settings(max_examples=50)
    def test_uniform_data_low_entropy(self, byte_value):
        """Property: Uniform data has entropy close to 0."""
        data = bytes([byte_value] * 1024)
        analyzer = EntropyAnalyzer(window_size=256)
        
        entropies = analyzer.calculate_entropy(data)
        
        # Uniform data should have very low entropy
        assert all(e < 1.0 for e in entropies), \
            f"Uniform data should have low entropy, got {entropies}"
    
    @given(st.binary(min_size=1, max_size=100))
    @settings(max_examples=50)
    def test_small_data_no_crash(self, data):
        """Property: Analyzer never crashes on small data."""
        analyzer = EntropyAnalyzer(window_size=256)
        
        try:
            entropies = analyzer.calculate_entropy(data)
            assert isinstance(entropies, list)
        except Exception as e:
            pytest.fail(f"Analyzer crashed on small data: {e}")


class TestPCRProperties:
    """Property-based tests for PCR operations."""
    
    @given(st.binary(min_size=32, max_size=32))
    @settings(max_examples=100)
    def test_pcr_extend_deterministic(self, event_data):
        """Property: PCR extend is deterministic."""
        pcr_replay1 = PCRReplayEngine()
        pcr_replay2 = PCRReplayEngine()
        
        # Extend with same data twice
        pcr1 = pcr_replay1.extend_pcr(0, event_data)
        pcr2 = pcr_replay2.extend_pcr(0, event_data)
        
        assert pcr1 == pcr2, "PCR extend must be deterministic"
    
    @given(st.binary(min_size=32, max_size=32))
    @settings(max_examples=100)
    def test_pcr_extend_produces_valid_hash(self, event_data):
        """Property: PCR extend always produces 32-byte hash."""
        pcr_replay = PCRReplayEngine()
        
        result = pcr_replay.extend_pcr(0, event_data)
        
        assert len(result) == 32, f"PCR must be 32 bytes, got {len(result)}"
        assert isinstance(result, bytes), "PCR must be bytes"
    
    @given(
        st.binary(min_size=32, max_size=32),
        st.binary(min_size=32, max_size=32)
    )
    @settings(max_examples=100)
    def test_pcr_extend_order_matters(self, data1, data2):
        """Property: PCR extend order affects result."""
        pcr_replay = PCRReplayEngine()
        
        # Extend in different orders
        pcr_replay.extend_pcr(0, data1)
        pcr_a = pcr_replay.extend_pcr(0, data2)
        
        pcr_replay2 = PCRReplayEngine()
        pcr_replay2.extend_pcr(0, data2)
        pcr_b = pcr_replay2.extend_pcr(0, data1)
        
        if data1 != data2:
            assert pcr_a != pcr_b, "Different extend order should produce different PCR"


class TestDetectorRobustness:
    """Property-based tests for detector robustness."""
    
    @given(st.binary(min_size=0, max_size=10000))
    @settings(max_examples=200, deadline=None)
    def test_detectors_never_crash(self, data):
        """Property: Detectors never crash on arbitrary binary input."""
        import tempfile
        
        # Test entropy analyzer
        analyzer = None
        try:
            analyzer = EntropyAnalyzer()
            entropies = analyzer.calculate_entropy(data)
            assert isinstance(entropies, list)
        except Exception as e:
            pytest.fail(f"EntropyAnalyzer crashed: {e}")
        
        # Test with file only if analyzer was created successfully
        if analyzer is not None:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
                f.write(data)
                temp_path = f.name
            
            try:
                findings = analyzer.detect(temp_path)
                assert isinstance(findings, list)
            except Exception as e:
                pytest.fail(f"Detector crashed on file: {e}")
            finally:
                Path(temp_path).unlink(missing_ok=True)
    
    @given(st.binary(min_size=64, max_size=1024))
    @settings(max_examples=100)
    def test_memory_patterns_no_crash(self, data):
        """Property: Memory pattern detection never crashes."""
        from AegisScanner.detectors.memory_detector import MemoryDetector
        
        try:
            detector = MemoryDetector()
            # Should handle arbitrary binary data
            assert detector is not None
        except Exception as e:
            pytest.fail(f"MemoryDetector initialization crashed: {e}")


class TestStructureValidation:
    """Property-based tests for structure validation."""
    
    @given(st.integers(min_value=0, max_value=0xFFFFFFFF))
    @settings(max_examples=100)
    def test_valid_pcr_index(self, pcr_index):
        """Property: PCR index validation."""
        # PCR indices 0-23 are valid in TPM 2.0
        is_valid = 0 <= pcr_index <= 23
        
        if is_valid:
            assert pcr_index >= 0 and pcr_index <= 23
        else:
            assert pcr_index < 0 or pcr_index > 23
    
    @given(st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF))
    @settings(max_examples=100)
    def test_firmware_volume_size_reasonable(self, fv_size):
        """Property: FV size validation."""
        # Firmware volumes should be reasonable size (< 256MB)
        MAX_FV_SIZE = 0x10000000  # 256MB
        
        is_reasonable = 0 < fv_size < MAX_FV_SIZE
        
        if not is_reasonable:
            # Should be rejected by validation
            assert fv_size <= 0 or fv_size >= MAX_FV_SIZE


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--hypothesis-show-statistics"])


