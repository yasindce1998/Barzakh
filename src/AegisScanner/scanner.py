#!/usr/bin/env python3
"""
Aegis-Boot Scanner - Bootkit Detection Engine

This scanner analyzes firmware, memory, and boot measurements to detect
bootkit artifacts with high accuracy and low false positive rates.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Detection modules
try:
    from .detectors.pcr_detector import PCRDetector
    from .detectors.memory_detector import MemoryDetector
    from .detectors.hook_detector_v2 import HookDetectorV2
    from .detectors.eventlog_detector import EventLogDetector
    from .detectors.entropy_analyzer import EntropyAnalyzer
    from .detectors.secure_boot_detector import SecureBootDetector
    from .detectors.runtime_hook_detector import RuntimeHookDetector
    from .detectors.smm_detector import SMMDetector
    from .detectors.fv_parser import FirmwareVolumeParser
    from .detectors.spi_integrity_detector import SpiIntegrityDetector
    from .detectors.self_erasure_detector import SelfErasureDetector
    from .pcr_oracle.oracle import PCROracle
    from .reports.report_generator import ReportGenerator
except ImportError:
    from detectors.pcr_detector import PCRDetector
    from detectors.memory_detector import MemoryDetector
    from detectors.hook_detector_v2 import HookDetectorV2
    from detectors.eventlog_detector import EventLogDetector
    from detectors.entropy_analyzer import EntropyAnalyzer
    from detectors.secure_boot_detector import SecureBootDetector
    from detectors.runtime_hook_detector import RuntimeHookDetector
    from detectors.smm_detector import SMMDetector
    from detectors.fv_parser import FirmwareVolumeParser
    from detectors.spi_integrity_detector import SpiIntegrityDetector
    from detectors.self_erasure_detector import SelfErasureDetector
    from pcr_oracle.oracle import PCROracle
    from reports.report_generator import ReportGenerator


class AegisScanner:
    """Main scanner engine for bootkit detection."""

    def __init__(self, baseline_path: Optional[str] = None, use_enhanced_hook_detector: bool = True):
        """
        Initialize the scanner.

        Args:
            baseline_path: Path to baseline configuration file
            use_enhanced_hook_detector: Use HookDetectorV2 with FV validation (default: True)
        """
        self.baseline = self._load_baseline(baseline_path) if baseline_path else None
        
        # Initialize detectors
        self.detectors = {
            'pcr': PCRDetector(self.baseline),
            'memory': MemoryDetector(self.baseline),
            'hook': HookDetectorV2(self.baseline),
            'eventlog': EventLogDetector(self.baseline),
            'entropy': EntropyAnalyzer(),
            'secureboot': SecureBootDetector(self.baseline),
            'runtime': RuntimeHookDetector(self.baseline),
            'smm': SMMDetector(self.baseline),
            'firmware_volume': FirmwareVolumeParser(),
            'spi_integrity': SpiIntegrityDetector(self.baseline),
            'self_erasure': SelfErasureDetector(self.baseline),
            'pcr_oracle': PCROracle(),
        }
        self.use_enhanced_hook_detector = use_enhanced_hook_detector
        self.findings = []
        self.scan_start_time = None
        self.scan_end_time = None

    def _load_baseline(self, baseline_path: str) -> Dict:
        """Load baseline configuration."""
        try:
            with open(baseline_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[ERROR] Failed to load baseline: {e}")
            return {}

    def scan(self, target_path: str, scan_types: Optional[List[str]] = None) -> Dict:
        """
        Perform comprehensive bootkit scan.

        Args:
            target_path: Path to firmware/memory dump to scan
            scan_types: List of scan types to perform (default: all)

        Returns:
            Dictionary containing scan results
        """
        self.scan_start_time = datetime.now()
        print(f"\n{'='*60}")
        print(f"Aegis-Boot Scanner v1.0")
        print(f"{'='*60}")
        print(f"Target: {target_path}")
        print(f"Baseline: {'Loaded' if self.baseline else 'None'}")
        print(f"Start Time: {self.scan_start_time.isoformat()}")
        print(f"{'='*60}\n")

        # Determine which scans to run
        if scan_types is None:
            scan_types = list(self.detectors.keys())

        # Run each detector
        for scan_type in scan_types:
            if scan_type in self.detectors:
                print(f"[*] Running {scan_type.upper()} detection...")
                try:
                    results = self.detectors[scan_type].detect(target_path)
                    self.findings.extend(results)
                    print(f"    Found {len(results)} potential issues")
                except Exception as e:
                    print(f"    [ERROR] {scan_type} detection failed: {e}")

        self.scan_end_time = datetime.now()
        scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()

        # Generate summary
        summary = self._generate_summary(scan_duration)
        
        print(f"\n{'='*60}")
        print(f"Scan Complete")
        print(f"{'='*60}")
        print(f"Duration: {scan_duration:.2f} seconds")
        print(f"Total Findings: {len(self.findings)}")
        print(f"Critical: {summary['critical_count']}")
        print(f"High: {summary['high_count']}")
        print(f"Medium: {summary['medium_count']}")
        print(f"Low: {summary['low_count']}")
        print(f"{'='*60}\n")

        return {
            'summary': summary,
            'findings': self.findings,
            'scan_info': {
                'target': target_path,
                'start_time': self.scan_start_time.isoformat(),
                'end_time': self.scan_end_time.isoformat(),
                'duration_seconds': scan_duration
            }
        }

    def _generate_summary(self, duration: float) -> Dict:
        """Generate scan summary statistics."""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        for finding in self.findings:
            severity = finding.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        return {
            'total_findings': len(self.findings),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'scan_duration': duration,
            'bootkit_detected': severity_counts['critical'] > 0 or severity_counts['high'] > 0
        }

    def generate_report(self, output_path: str, format: str = 'html'):
        """
        Generate detection report.

        Args:
            output_path: Path to save report
            format: Report format ('html', 'json', 'markdown')
        """
        print(f"[*] Generating {format.upper()} report...")
        
        report_gen = ReportGenerator(self.findings, self.baseline)
        
        if format == 'html':
            report_gen.generate_html(output_path)
        elif format == 'json':
            report_gen.generate_json(output_path)
        elif format == 'markdown':
            report_gen.generate_markdown(output_path)
        else:
            print(f"[ERROR] Unknown report format: {format}")
            return

        print(f"[+] Report saved to: {output_path}")

    def validate_against_corpus(self, corpus_path: str) -> Dict:
        """
        Validate scanner against test corpus.

        Args:
            corpus_path: Path to test corpus directory

        Returns:
            Validation metrics (TPR, FPR, ROC-AUC)
        """
        print(f"\n[*] Validating against test corpus: {corpus_path}")
        
        corpus_dir = Path(corpus_path)
        if not corpus_dir.exists():
            print(f"[ERROR] Corpus directory not found: {corpus_path}")
            return {}

        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0

        # Scan infected samples
        infected_dir = corpus_dir / 'infected'
        if infected_dir.exists():
            infected_samples = list(infected_dir.glob('*'))
            print(f"[*] Scanning {len(infected_samples)} infected samples...")
            
            for sample in infected_samples:
                results = self.scan(str(sample), scan_types=['pcr', 'memory', 'hook'])
                if results['summary']['bootkit_detected']:
                    true_positives += 1
                else:
                    false_negatives += 1

        # Scan clean samples
        clean_dir = corpus_dir / 'clean'
        if clean_dir.exists():
            clean_samples = list(clean_dir.glob('*'))
            print(f"[*] Scanning {len(clean_samples)} clean samples...")
            
            for sample in clean_samples:
                results = self.scan(str(sample), scan_types=['pcr', 'memory', 'hook'])
                if results['summary']['bootkit_detected']:
                    false_positives += 1
                else:
                    true_negatives += 1

        # Calculate metrics
        total_infected = true_positives + false_negatives
        total_clean = true_negatives + false_positives
        
        tpr = true_positives / total_infected if total_infected > 0 else 0
        fpr = false_positives / total_clean if total_clean > 0 else 0
        
        metrics = {
            'true_positives': true_positives,
            'false_positives': false_positives,
            'true_negatives': true_negatives,
            'false_negatives': false_negatives,
            'true_positive_rate': tpr,
            'false_positive_rate': fpr,
            'accuracy': (true_positives + true_negatives) / (total_infected + total_clean) if (total_infected + total_clean) > 0 else 0
        }

        print(f"\n{'='*60}")
        print(f"Validation Results")
        print(f"{'='*60}")
        print(f"True Positives:  {true_positives}/{total_infected}")
        print(f"False Positives: {false_positives}/{total_clean}")
        print(f"TPR: {tpr*100:.2f}% (Target: ≥85%)")
        print(f"FPR: {fpr*100:.2f}% (Target: <5%)")
        print(f"Accuracy: {metrics['accuracy']*100:.2f}%")
        print(f"{'='*60}\n")

        return metrics


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Aegis-Boot Scanner - Bootkit Detection Engine'
    )
    
    parser.add_argument(
        '--target',
        help='Path to firmware/memory dump to scan'
    )
    
    parser.add_argument(
        '--baseline',
        help='Path to baseline configuration file'
    )
    
    parser.add_argument(
        '--scan-types',
        nargs='+',
        choices=[
            'pcr', 'memory', 'hook', 'eventlog', 'entropy',
            'secureboot', 'runtime', 'smm', 'firmware_volume',
            'spi_integrity', 'self_erasure', 'pcr_oracle'
        ],
        help='Types of scans to perform (default: all)'
    )
    
    parser.add_argument(
        '--report',
        action='store_true',
        help='Generate detection report'
    )
    
    parser.add_argument(
        '--output',
        default='aegis_report.html',
        help='Output path for report'
    )
    
    parser.add_argument(
        '--format',
        choices=['html', 'json', 'markdown'],
        default='html',
        help='Report format'
    )
    
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate against test corpus'
    )
    
    parser.add_argument(
        '--corpus',
        help='Path to test corpus directory'
    )

    args = parser.parse_args()

    # Initialize scanner
    scanner = AegisScanner(baseline_path=args.baseline)

    # Validation mode
    if args.validate:
        if not args.corpus:
            print("[ERROR] --corpus required for validation mode")
            sys.exit(1)
        
        metrics = scanner.validate_against_corpus(args.corpus)
        
        # Save metrics
        with open('validation_metrics.json', 'w') as f:
            json.dump(metrics, f, indent=2)
        
        print(f"[+] Metrics saved to: validation_metrics.json")
        sys.exit(0)

    # Scan mode
    if not args.target:
        print("[ERROR] --target required for scan mode")
        parser.print_help()
        sys.exit(1)

    # Perform scan
    results = scanner.scan(args.target, scan_types=args.scan_types)

    # Generate report if requested
    if args.report:
        scanner.generate_report(args.output, format=args.format)

    # Save results
    results_file = 'scan_results.json'
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"[+] Results saved to: {results_file}")

    # Exit with appropriate code
    sys.exit(1 if results['summary']['bootkit_detected'] else 0)


if __name__ == '__main__':
    main()


