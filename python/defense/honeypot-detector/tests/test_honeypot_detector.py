#!/usr/bin/env python3
"""
Unit tests for Honeypot Detector tool.

Tests cover:
- Data classes
- Detection techniques
- Probability calculation
- Planning mode
- Output formatting
"""

import json
import sys
import unittest
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from tool import (
    HoneypotIndicator,
    TargetAnalysis,
    DetectionResult,
    HoneypotDetector,
    BannerAnalyzer,
    TimingAnalyzer,
    ServiceBehaviorAnalyzer,
    NetworkAnalyzer,
    KnownHoneypotDetector,
    ServiceProber,
    get_documentation,
    format_output_text,
    format_output_json,
)


class TestHoneypotIndicator(unittest.TestCase):
    """Tests for HoneypotIndicator data class."""

    def test_create_indicator(self):
        """Test indicator creation."""
        indicator = HoneypotIndicator(
            indicator_type="banner",
            name="cowrie",
            description="Cowrie honeypot detected",
            confidence="HIGH",
            evidence="SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4",
            target="192.168.1.100:22",
        )

        self.assertEqual(indicator.indicator_type, "banner")
        self.assertEqual(indicator.name, "cowrie")
        self.assertEqual(indicator.confidence, "HIGH")

    def test_indicator_to_dict(self):
        """Test indicator serialization."""
        indicator = HoneypotIndicator(
            indicator_type="timing",
            name="instant_response",
            description="Fast response",
            confidence="LOW",
            evidence="2ms response",
            target="10.0.0.1:80",
        )

        data = indicator.to_dict()

        self.assertEqual(data["indicator_type"], "timing")
        self.assertEqual(data["name"], "instant_response")


class TestTargetAnalysis(unittest.TestCase):
    """Tests for TargetAnalysis data class."""

    def test_create_analysis(self):
        """Test analysis creation."""
        analysis = TargetAnalysis(
            target="192.168.1.100",
            port=22,
            service="ssh",
            indicators=[],
            honeypot_probability=0.3,
            analysis_time=datetime.now(),
        )

        self.assertEqual(analysis.target, "192.168.1.100")
        self.assertEqual(analysis.port, 22)
        self.assertFalse(analysis.is_likely_honeypot)

    def test_is_likely_honeypot(self):
        """Test honeypot likelihood calculation."""
        # Below threshold
        analysis_low = TargetAnalysis(
            target="192.168.1.100",
            port=22,
            service="ssh",
            indicators=[],
            honeypot_probability=0.5,
            analysis_time=datetime.now(),
        )
        self.assertFalse(analysis_low.is_likely_honeypot)

        # At threshold
        analysis_high = TargetAnalysis(
            target="192.168.1.100",
            port=22,
            service="ssh",
            indicators=[],
            honeypot_probability=0.6,
            analysis_time=datetime.now(),
        )
        self.assertTrue(analysis_high.is_likely_honeypot)

    def test_analysis_to_dict(self):
        """Test analysis serialization."""
        analysis = TargetAnalysis(
            target="10.0.0.1",
            port=80,
            service="http",
            indicators=[],
            honeypot_probability=0.75,
            analysis_time=datetime.now(),
        )

        data = analysis.to_dict()

        self.assertEqual(data["target"], "10.0.0.1")
        self.assertEqual(data["honeypot_probability"], 0.75)
        self.assertTrue(data["is_likely_honeypot"])


class TestBannerAnalyzer(unittest.TestCase):
    """Tests for banner analysis technique."""

    def setUp(self):
        self.analyzer = BannerAnalyzer()

    def test_detect_cowrie_banner(self):
        """Test detection of Cowrie honeypot banner."""
        service_info = {
            'banner': 'SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u4'
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        self.assertGreater(len(indicators), 0)
        high_conf = [i for i in indicators if i.confidence == "HIGH"]
        self.assertGreater(len(high_conf), 0)

    def test_detect_kippo_banner(self):
        """Test detection of Kippo honeypot banner."""
        service_info = {
            'banner': 'SSH-2.0-OpenSSH_5.1p1 Debian-5'
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        kippo_indicators = [i for i in indicators if 'kippo' in i.name.lower()]
        self.assertGreater(len(kippo_indicators), 0)

    def test_no_indicators_for_normal_banner(self):
        """Test no indicators for normal banner."""
        service_info = {
            'banner': 'SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2.1'
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        high_conf = [i for i in indicators if i.confidence == "HIGH"]
        self.assertEqual(len(high_conf), 0)

    def test_empty_banner(self):
        """Test handling of empty banner."""
        service_info = {'banner': ''}

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        self.assertEqual(len(indicators), 0)


class TestTimingAnalyzer(unittest.TestCase):
    """Tests for timing analysis technique."""

    def setUp(self):
        self.analyzer = TimingAnalyzer()

    def test_detect_instant_response(self):
        """Test detection of instant response."""
        service_info = {
            'response_time_ms': 2,
            'connection_time_ms': 5,
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        instant_indicators = [i for i in indicators if 'instant' in i.name.lower()]
        self.assertGreater(len(instant_indicators), 0)

    def test_detect_consistent_timing(self):
        """Test detection of consistent timing."""
        service_info = {
            'timing_variance': 0.1,
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        timing_indicators = [i for i in indicators if 'consistent' in i.name.lower()]
        self.assertGreater(len(timing_indicators), 0)

    def test_normal_timing(self):
        """Test no indicators for normal timing."""
        service_info = {
            'response_time_ms': 50,
            'timing_variance': 5.0,
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        self.assertEqual(len(indicators), 0)


class TestServiceBehaviorAnalyzer(unittest.TestCase):
    """Tests for service behavior analysis."""

    def setUp(self):
        self.analyzer = ServiceBehaviorAnalyzer()

    def test_detect_unusual_port_service(self):
        """Test detection of unusual port/service combination."""
        service_info = {
            'service': 'ssh',
        }

        indicators = self.analyzer.analyze("192.168.1.100", 80, service_info)

        unusual_indicators = [i for i in indicators if 'unusual' in i.name.lower()]
        self.assertGreater(len(unusual_indicators), 0)

    def test_detect_many_open_ports(self):
        """Test detection of excessive open ports."""
        service_info = {
            'other_open_ports': list(range(100)),
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        port_indicators = [i for i in indicators if 'ports' in i.name.lower()]
        self.assertGreater(len(port_indicators), 0)

    def test_detect_accepts_any_credentials(self):
        """Test detection of accepting any credentials."""
        service_info = {
            'accepts_any_credentials': True,
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        accepts_indicators = [i for i in indicators if 'accepts' in i.name.lower()]
        self.assertGreater(len(accepts_indicators), 0)


class TestNetworkAnalyzer(unittest.TestCase):
    """Tests for network analysis technique."""

    def setUp(self):
        self.analyzer = NetworkAnalyzer()

    def test_detect_unusual_ttl(self):
        """Test detection of unusual TTL."""
        service_info = {
            'ttl': 200,  # Not a common OS TTL
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        ttl_indicators = [i for i in indicators if 'ttl' in i.name.lower()]
        self.assertGreater(len(ttl_indicators), 0)

    def test_detect_identical_fingerprints(self):
        """Test detection of identical service fingerprints."""
        service_info = {
            'service_fingerprints': ['fp1', 'fp1', 'fp1', 'fp1'],
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        fp_indicators = [i for i in indicators if 'fingerprint' in i.name.lower()]
        self.assertGreater(len(fp_indicators), 0)

    def test_normal_ttl(self):
        """Test no indicators for normal TTL."""
        service_info = {
            'ttl': 64,  # Linux default
        }

        indicators = self.analyzer.analyze("192.168.1.100", 22, service_info)

        ttl_indicators = [i for i in indicators if 'ttl' in i.name.lower()]
        self.assertEqual(len(ttl_indicators), 0)


class TestKnownHoneypotDetector(unittest.TestCase):
    """Tests for known honeypot detection."""

    def setUp(self):
        self.detector = KnownHoneypotDetector()

    def test_detect_cowrie_signature(self):
        """Test detection of Cowrie signature."""
        service_info = {
            'banner': 'cowrie',
            'response': '',
        }

        indicators = self.detector.analyze("192.168.1.100", 22, service_info)

        cowrie_indicators = [i for i in indicators if 'cowrie' in i.name.lower()]
        self.assertGreater(len(cowrie_indicators), 0)

    def test_detect_honeyd_signature(self):
        """Test detection of HoneyD signature."""
        service_info = {
            'banner': 'honeyd virtual host',
            'response': '',
        }

        indicators = self.detector.analyze("192.168.1.100", 22, service_info)

        honeyd_indicators = [i for i in indicators if 'honeyd' in i.name.lower()]
        self.assertGreater(len(honeyd_indicators), 0)

    def test_detect_characteristic_port(self):
        """Test detection of characteristic honeypot port."""
        service_info = {
            'banner': '',
            'response': '',
        }

        # Port 2222 is commonly used by Cowrie/Kippo
        indicators = self.detector.analyze("192.168.1.100", 2222, service_info)

        port_indicators = [i for i in indicators if 'cowrie' in i.name.lower() or 'kippo' in i.name.lower()]
        self.assertGreater(len(port_indicators), 0)


class TestServiceProber(unittest.TestCase):
    """Tests for service prober."""

    def setUp(self):
        self.prober = ServiceProber(timeout=1.0)

    def test_identify_service_by_port(self):
        """Test service identification by port."""
        self.assertEqual(self.prober._identify_service(22, ''), 'ssh')
        self.assertEqual(self.prober._identify_service(80, ''), 'http')
        self.assertEqual(self.prober._identify_service(443, ''), 'https')
        self.assertEqual(self.prober._identify_service(21, ''), 'ftp')

    def test_identify_service_by_banner(self):
        """Test service identification by banner."""
        self.assertEqual(self.prober._identify_service(9999, 'SSH-2.0-OpenSSH'), 'ssh')
        self.assertEqual(self.prober._identify_service(9999, '220 FTP Server'), 'ftp')
        self.assertEqual(self.prober._identify_service(9999, 'HTTP/1.1 200 OK'), 'http')

    def test_identify_unknown_service(self):
        """Test unknown service identification."""
        self.assertEqual(self.prober._identify_service(9999, 'random banner'), 'unknown')


class TestHoneypotDetector(unittest.TestCase):
    """Tests for main HoneypotDetector class."""

    def setUp(self):
        self.detector = HoneypotDetector(timeout=1.0)

    def test_calculate_probability_no_indicators(self):
        """Test probability calculation with no indicators."""
        probability = self.detector._calculate_probability([])
        self.assertEqual(probability, 0.0)

    def test_calculate_probability_high_confidence(self):
        """Test probability calculation with high confidence indicator."""
        indicators = [
            HoneypotIndicator(
                indicator_type="banner",
                name="cowrie",
                description="Test",
                confidence="HIGH",
                evidence="",
                target="test",
            )
        ]

        probability = self.detector._calculate_probability(indicators)
        self.assertEqual(probability, 0.5)

    def test_calculate_probability_multiple_indicators(self):
        """Test probability calculation with multiple indicators."""
        indicators = [
            HoneypotIndicator(
                indicator_type="banner",
                name="test1",
                description="Test",
                confidence="HIGH",
                evidence="",
                target="test",
            ),
            HoneypotIndicator(
                indicator_type="timing",
                name="test2",
                description="Test",
                confidence="MEDIUM",
                evidence="",
                target="test",
            ),
        ]

        probability = self.detector._calculate_probability(indicators)
        self.assertEqual(probability, 0.8)  # 0.5 + 0.3

    def test_calculate_probability_capped(self):
        """Test probability is capped at 0.95."""
        indicators = [
            HoneypotIndicator(
                indicator_type="banner",
                name=f"test{i}",
                description="Test",
                confidence="HIGH",
                evidence="",
                target="test",
            )
            for i in range(10)
        ]

        probability = self.detector._calculate_probability(indicators)
        self.assertEqual(probability, 0.95)

    def test_plan_mode(self):
        """Test planning mode output."""
        targets = [("192.168.1.100", 22)]

        plan = self.detector.get_plan(targets, "text")

        self.assertIn("[PLAN MODE]", plan)
        self.assertIn("honeypot-detector", plan)
        self.assertIn("192.168.1.100", plan)
        self.assertIn("No actions will be taken", plan)


class TestDetectionResult(unittest.TestCase):
    """Tests for DetectionResult data class."""

    def test_duration_calculation(self):
        """Test duration calculation."""
        start = datetime.now()
        end = datetime.now()

        result = DetectionResult(
            targets_analyzed=1,
            honeypots_detected=0,
            analyses=[],
            start_time=start,
            end_time=end,
            summary="Test",
        )

        self.assertGreaterEqual(result.duration, 0)

    def test_to_dict(self):
        """Test serialization."""
        result = DetectionResult(
            targets_analyzed=2,
            honeypots_detected=1,
            analyses=[],
            start_time=datetime.now(),
            end_time=datetime.now(),
            summary="Test summary",
        )

        data = result.to_dict()

        self.assertEqual(data["targets_analyzed"], 2)
        self.assertEqual(data["honeypots_detected"], 1)


class TestOutputFormatters(unittest.TestCase):
    """Tests for output formatters."""

    def setUp(self):
        self.result = DetectionResult(
            targets_analyzed=1,
            honeypots_detected=1,
            analyses=[
                TargetAnalysis(
                    target="192.168.1.100",
                    port=22,
                    service="ssh",
                    indicators=[
                        HoneypotIndicator(
                            indicator_type="banner",
                            name="cowrie",
                            description="Cowrie detected",
                            confidence="HIGH",
                            evidence="SSH-2.0-OpenSSH_6.0p1",
                            target="192.168.1.100:22",
                        )
                    ],
                    honeypot_probability=0.85,
                    analysis_time=datetime.now(),
                )
            ],
            start_time=datetime.now(),
            end_time=datetime.now(),
            summary="Detected 1 honeypot",
        )

    def test_text_output(self):
        """Test text format output."""
        output = format_output_text(self.result)

        self.assertIn("HONEYPOT DETECTION REPORT", output)
        self.assertIn("192.168.1.100", output)
        self.assertIn("85.0%", output)
        self.assertIn("LIKELY HONEYPOT", output)
        self.assertIn("cowrie", output)

    def test_json_output(self):
        """Test JSON format output."""
        output = format_output_json(self.result)
        data = json.loads(output)

        self.assertEqual(data["targets_analyzed"], 1)
        self.assertEqual(data["honeypots_detected"], 1)
        self.assertEqual(len(data["analyses"]), 1)
        self.assertTrue(data["analyses"][0]["is_likely_honeypot"])


class TestDocumentation(unittest.TestCase):
    """Tests for documentation function."""

    def test_documentation_structure(self):
        """Test documentation returns required fields."""
        docs = get_documentation()

        self.assertIn("name", docs)
        self.assertIn("category", docs)
        self.assertIn("version", docs)
        self.assertIn("description", docs)
        self.assertIn("features", docs)
        self.assertIn("usage_examples", docs)
        self.assertIn("detection_techniques", docs)
        self.assertEqual(docs["name"], "honeypot-detector")

    def test_documentation_includes_honeypots(self):
        """Test documentation includes known honeypots."""
        docs = get_documentation()

        self.assertIn("known_honeypots", docs)
        self.assertIn("cowrie", docs["known_honeypots"])
        self.assertIn("kippo", docs["known_honeypots"])


if __name__ == '__main__':
    unittest.main(verbosity=2)
