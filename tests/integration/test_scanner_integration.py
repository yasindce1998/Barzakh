"""
Integration tests for Aegis-Boot Scanner

Tests the complete scanner workflow including all detectors and report generation.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import pytest
import tempfile
import json
from pathlib import Path
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from src.AegisScanner.scanner import AegisScanner


class TestScannerIntegration:
    """Integration test suite for complete scanner workflow."""

    def setup_method(self):
        """Setup test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.scanner = AegisScanner()

    def teardown_method(self):
        """Cleanup test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_scanner_initialization(self):
        """Test scanner initializes correctly."""
        assert self.scanner is not None
        assert self.scanner.baseline is None
        assert len(self.scanner.detectors) == 12
        assert 'pcr' in self.scanner.detectors
        assert 'memory' in self.scanner.detectors
        assert 'hook' in self.scanner.detectors
        assert 'eventlog' in self.scanner.detectors
        assert 'entropy' in self.scanner.detectors
        assert 'secureboot' in self.scanner.detectors
        assert 'runtime' in self.scanner.detectors
        assert 'smm' in self.scanner.detectors
        assert 'firmware_volume' in self.scanner.detectors
        assert 'spi_integrity' in self.scanner.detectors
        assert 'self_erasure' in self.scanner.detectors

    def test_scanner_with_baseline(self):
        """Test scanner with baseline configuration."""
        baseline_file = Path(self.temp_dir) / 'baseline.json'
        baseline_data = {
            'pcr_values': {'0': 'a' * 64},
            'memory_map': [],
            'boot_services_table': {},
            'event_log': []
        }
        
        with open(baseline_file, 'w') as f:
            json.dump(baseline_data, f)
        
        scanner = AegisScanner(baseline_path=str(baseline_file))
        assert scanner.baseline is not None

    def test_full_scan_workflow(self):
        """Test complete scan workflow."""
        # Create test target
        test_file = Path(self.temp_dir) / 'test_target.bin'
        test_data = b'\x00' * 1024
        with open(test_file, 'wb') as f:
            f.write(test_data)
        
        # Run scan
        results = self.scanner.scan(str(test_file))
        
        # Verify results structure
        assert 'summary' in results
        assert 'findings' in results
        assert 'scan_info' in results
        
        # Verify summary
        summary = results['summary']
        assert 'total_findings' in summary
        assert 'critical_count' in summary
        assert 'high_count' in summary
        assert 'medium_count' in summary
        assert 'low_count' in summary
        assert 'bootkit_detected' in summary
        
        # Verify scan info
        scan_info = results['scan_info']
        assert 'target' in scan_info
        assert 'start_time' in scan_info
        assert 'end_time' in scan_info
        assert 'duration_seconds' in scan_info

    def test_scan_with_specific_types(self):
        """Test scan with specific detector types."""
        test_file = Path(self.temp_dir) / 'test_target.bin'
        test_data = b'\x00' * 1024
        with open(test_file, 'wb') as f:
            f.write(test_data)
        
        # Run scan with only PCR detection
        results = self.scanner.scan(str(test_file), scan_types=['pcr'])
        
        assert 'findings' in results
        # All findings should be from PCR detector
        for finding in results['findings']:
            assert finding.get('detector') == 'pcr'

    def test_report_generation_html(self):
        """Test HTML report generation."""
        # Create test target and scan
        test_file = Path(self.temp_dir) / 'test_target.bin'
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        self.scanner.scan(str(test_file))
        
        # Generate HTML report
        report_file = Path(self.temp_dir) / 'report.html'
        self.scanner.generate_report(str(report_file), format='html')
        
        # Verify report was created
        assert report_file.exists()
        
        # Verify report contains expected content
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
            assert 'Aegis-Boot Scanner Report' in content
            assert 'summary' in content

    def test_report_generation_json(self):
        """Test JSON report generation."""
        test_file = Path(self.temp_dir) / 'test_target.bin'
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        self.scanner.scan(str(test_file))
        
        # Generate JSON report
        report_file = Path(self.temp_dir) / 'report.json'
        self.scanner.generate_report(str(report_file), format='json')
        
        # Verify report was created
        assert report_file.exists()
        
        # Verify report is valid JSON
        with open(report_file, 'r') as f:
            report_data = json.load(f)
            assert 'timestamp' in report_data
            assert 'summary' in report_data
            assert 'findings' in report_data

    def test_report_generation_markdown(self):
        """Test Markdown report generation."""
        test_file = Path(self.temp_dir) / 'test_target.bin'
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * 1024)
        
        self.scanner.scan(str(test_file))
        
        # Generate Markdown report
        report_file = Path(self.temp_dir) / 'report.md'
        self.scanner.generate_report(str(report_file), format='markdown')
        
        # Verify report was created
        assert report_file.exists()
        
        # Verify report contains expected content
        with open(report_file, 'r', encoding='utf-8') as f:
            content = f.read()
            assert '# Aegis-Boot Scanner Report' in content
            assert '## Summary' in content

    def test_scan_performance(self):
        """Test scan completes within acceptable time."""
        test_file = Path(self.temp_dir) / 'test_target.bin'
        # Create larger test file
        with open(test_file, 'wb') as f:
            f.write(b'\x00' * (1024 * 1024))  # 1MB
        
        results = self.scanner.scan(str(test_file))
        
        # Verify scan completed in reasonable time (< 30 seconds)
        duration = results['scan_info']['duration_seconds']
        assert duration < 30.0

    def test_multiple_scans(self):
        """Test scanner can perform multiple scans."""
        test_file1 = Path(self.temp_dir) / 'test1.bin'
        test_file2 = Path(self.temp_dir) / 'test2.bin'
        
        with open(test_file1, 'wb') as f:
            f.write(b'\x00' * 1024)
        with open(test_file2, 'wb') as f:
            f.write(b'\xff' * 1024)
        
        # First scan
        results1 = self.scanner.scan(str(test_file1))
        assert 'summary' in results1
        
        # Reset findings
        self.scanner.findings = []
        
        # Second scan
        results2 = self.scanner.scan(str(test_file2))
        assert 'summary' in results2

    def test_scan_with_invalid_target(self):
        """Test scan handles invalid target gracefully."""
        results = self.scanner.scan('/nonexistent/file.bin')
        
        # Should still return valid results structure
        assert 'summary' in results
        assert 'findings' in results
        
        # Should have findings about missing file
        assert len(results['findings']) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])


