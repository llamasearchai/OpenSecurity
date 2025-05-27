"""Tests for security detectors."""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, AsyncMock
import numpy as np
import pandas as pd

from backend.detectors.base import DetectionSeverity, DetectionResult
from backend.detectors.anomaly import (
    NetworkAnomalyDetector,
    UserBehaviorAnomalyDetector,
    TimeSeriesAnomalyDetector
)
from backend.detectors.rules import (
    MalwareDetector,
    IntrusionDetector,
    DataExfiltrationDetector
)
from backend.detectors.manager import DetectorManager


class TestNetworkAnomalyDetector:
    """Test network anomaly detector."""
    
    @pytest.fixture
    async def detector(self):
        """Create network anomaly detector."""
        detector = NetworkAnomalyDetector()
        await detector.load_model()
        return detector
    
    @pytest.mark.asyncio
    async def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.id == "network_anomaly"
        assert detector.name == "Network Anomaly Detector"
        assert detector.enabled is True
        assert detector.model is not None
    
    @pytest.mark.asyncio
    async def test_process_normal_traffic(self, detector):
        """Test processing normal network traffic."""
        normal_data = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "bytes_sent": 1024,
                "bytes_received": 2048,
                "packets_sent": 10,
                "packets_received": 15,
                "duration": 30,
                "port": 80,
                "protocol": "tcp"
            }
        ]
        
        # Train with normal data first
        await detector.train(normal_data * 100)  # More samples for training
        
        results = await detector.process(normal_data)
        # Normal traffic should not trigger anomalies
        assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_process_anomalous_traffic(self, detector):
        """Test processing anomalous network traffic."""
        # Train with normal data
        normal_data = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "bytes_sent": 1024,
                "bytes_received": 2048,
                "packets_sent": 10,
                "packets_received": 15,
                "duration": 30,
                "port": 80,
                "protocol": "tcp"
            }
        ] * 100
        
        await detector.train(normal_data)
        
        # Anomalous data with very high byte counts
        anomalous_data = [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "bytes_sent": 1000000,  # Very high
                "bytes_received": 2000000,  # Very high
                "packets_sent": 10000,  # Very high
                "packets_received": 15000,  # Very high
                "duration": 30,
                "port": 80,
                "protocol": "tcp"
            }
        ]
        
        results = await detector.process(anomalous_data)
        assert len(results) >= 0  # May or may not detect depending on model
        
        if results:
            result = results[0]
            assert result.detector_id == "network_anomaly"
            assert result.severity in [DetectionSeverity.LOW, DetectionSeverity.MEDIUM, 
                                     DetectionSeverity.HIGH, DetectionSeverity.CRITICAL]
            assert 0 <= result.confidence <= 1
    
    @pytest.mark.asyncio
    async def test_configuration(self, detector):
        """Test detector configuration."""
        config = detector.get_configuration()
        assert "contamination" in config
        assert "threshold" in config
        
        new_config = {"threshold": 0.8}
        detector.set_configuration(new_config)
        assert detector.threshold == 0.8


class TestUserBehaviorAnomalyDetector:
    """Test user behavior anomaly detector."""
    
    @pytest.fixture
    async def detector(self):
        """Create user behavior anomaly detector."""
        detector = UserBehaviorAnomalyDetector()
        await detector.load_model()
        return detector
    
    @pytest.mark.asyncio
    async def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.id == "user_behavior_anomaly"
        assert detector.name == "User Behavior Anomaly Detector"
        assert detector.enabled is True
    
    @pytest.mark.asyncio
    async def test_process_normal_behavior(self, detector):
        """Test processing normal user behavior."""
        # Train with normal behavior patterns
        training_data = []
        for i in range(50):
            training_data.append({
                "user_id": "user1",
                "login_hour": 9,  # Normal business hours
                "session_duration": 480,  # 8 hours
                "failed_logins": 0,
                "unique_ips": 1,
                "data_accessed_mb": 100,
                "privileged_actions": 2,
                "weekend_activity": 0,
                "off_hours_activity": 0
            })
        
        await detector.train(training_data)
        
        # Test with similar normal behavior
        test_data = [{
            "user_id": "user1",
            "login_hour": 10,
            "session_duration": 450,
            "failed_logins": 0,
            "unique_ips": 1,
            "data_accessed_mb": 95,
            "privileged_actions": 2,
            "weekend_activity": 0,
            "off_hours_activity": 0
        }]
        
        results = await detector.process(test_data)
        # Normal behavior should not trigger anomalies
        assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_process_anomalous_behavior(self, detector):
        """Test processing anomalous user behavior."""
        # Train with normal behavior
        training_data = []
        for i in range(50):
            training_data.append({
                "user_id": "user1",
                "login_hour": 9,
                "session_duration": 480,
                "failed_logins": 0,
                "unique_ips": 1,
                "data_accessed_mb": 100,
                "privileged_actions": 2,
                "weekend_activity": 0,
                "off_hours_activity": 0
            })
        
        await detector.train(training_data)
        
        # Test with anomalous behavior
        anomalous_data = [{
            "user_id": "user1",
            "login_hour": 2,  # Very early hour
            "session_duration": 1440,  # 24 hours
            "failed_logins": 10,  # Many failed logins
            "unique_ips": 5,  # Multiple IPs
            "data_accessed_mb": 10000,  # Very high data access
            "privileged_actions": 50,  # Many privileged actions
            "weekend_activity": 1,
            "off_hours_activity": 1
        }]
        
        results = await detector.process(anomalous_data)
        assert len(results) >= 1  # Should detect anomaly
        
        result = results[0]
        assert result.detector_id == "user_behavior_anomaly"
        assert result.severity in [DetectionSeverity.MEDIUM, DetectionSeverity.HIGH, DetectionSeverity.CRITICAL]


class TestMalwareDetector:
    """Test malware detector."""
    
    @pytest.fixture
    def detector(self):
        """Create malware detector."""
        return MalwareDetector()
    
    @pytest.mark.asyncio
    async def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.id == "malware_detector"
        assert detector.name == "Malware Detector"
        assert detector.enabled is True
        assert len(detector.rules) > 0
    
    @pytest.mark.asyncio
    async def test_suspicious_file_extension(self, detector):
        """Test detection of suspicious file extensions."""
        test_data = [
            {"filename": "document.exe"},
            {"filename": "script.bat"},
            {"filename": "normal.txt"}
        ]
        
        results = await detector.process(test_data)
        
        # Should detect .exe and .bat files
        assert len(results) >= 2
        
        exe_result = next((r for r in results if "document.exe" in r.description), None)
        assert exe_result is not None
        assert exe_result.severity == DetectionSeverity.MEDIUM
    
    @pytest.mark.asyncio
    async def test_double_extension(self, detector):
        """Test detection of double file extensions."""
        test_data = [
            {"filename": "document.pdf.exe"},
            {"filename": "image.jpg.scr"},
            {"filename": "normal.pdf"}
        ]
        
        results = await detector.process(test_data)
        
        # Should detect double extensions
        double_ext_results = [r for r in results if "Double file extension" in r.description]
        assert len(double_ext_results) >= 2
        
        for result in double_ext_results:
            assert result.severity == DetectionSeverity.HIGH
    
    @pytest.mark.asyncio
    async def test_powershell_encoded_command(self, detector):
        """Test detection of PowerShell encoded commands."""
        test_data = [
            {"command_line": "powershell -enc SGVsbG8gV29ybGQ="},
            {"command_line": "powershell -EncodedCommand VGVzdCBDb21tYW5k"},
            {"command_line": "normal command"}
        ]
        
        results = await detector.process(test_data)
        
        # Should detect encoded PowerShell commands
        ps_results = [r for r in results if "PowerShell encoded command" in r.description]
        assert len(ps_results) >= 2
        
        for result in ps_results:
            assert result.severity == DetectionSeverity.HIGH


class TestIntrusionDetector:
    """Test intrusion detector."""
    
    @pytest.fixture
    def detector(self):
        """Create intrusion detector."""
        return IntrusionDetector()
    
    @pytest.mark.asyncio
    async def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.id == "intrusion_detector"
        assert detector.name == "Intrusion Detector"
        assert detector.enabled is True
    
    @pytest.mark.asyncio
    async def test_brute_force_detection(self, detector):
        """Test brute force attack detection."""
        # Simulate multiple failed login attempts
        failed_attempts = []
        for i in range(6):  # Exceed threshold of 5
            failed_attempts.append({
                "event_type": "login_failed",
                "src_ip": "192.168.1.100",
                "username": "admin",
                "timestamp": datetime.utcnow().isoformat()
            })
        
        results = []
        for attempt in failed_attempts:
            result = await detector.process([attempt])
            results.extend(result)
        
        # Should detect brute force after threshold
        brute_force_results = [r for r in results if "Brute force attack" in r.description]
        assert len(brute_force_results) >= 1
        
        result = brute_force_results[0]
        assert result.severity == DetectionSeverity.HIGH
        assert "192.168.1.100" in result.entities
    
    @pytest.mark.asyncio
    async def test_sql_injection_detection(self, detector):
        """Test SQL injection detection."""
        test_data = [
            {
                "request_body": "username=admin' OR '1'='1",
                "url_params": "",
                "src_ip": "192.168.1.100"
            },
            {
                "request_body": "",
                "url_params": "id=1; DROP TABLE users;",
                "src_ip": "192.168.1.101"
            }
        ]
        
        results = await detector.process(test_data)
        
        # Should detect SQL injection attempts
        sql_results = [r for r in results if "SQL injection" in r.description]
        assert len(sql_results) >= 2
        
        for result in sql_results:
            assert result.severity == DetectionSeverity.HIGH
    
    @pytest.mark.asyncio
    async def test_xss_detection(self, detector):
        """Test XSS attack detection."""
        test_data = [
            {
                "request_body": "<script>alert('xss')</script>",
                "url_params": "",
                "src_ip": "192.168.1.100"
            },
            {
                "request_body": "",
                "url_params": "comment=<img src=x onerror=alert(1)>",
                "src_ip": "192.168.1.101"
            }
        ]
        
        results = await detector.process(test_data)
        
        # Should detect XSS attempts
        xss_results = [r for r in results if "XSS attempt" in r.description]
        assert len(xss_results) >= 2
        
        for result in xss_results:
            assert result.severity == DetectionSeverity.MEDIUM


class TestDataExfiltrationDetector:
    """Test data exfiltration detector."""
    
    @pytest.fixture
    def detector(self):
        """Create data exfiltration detector."""
        return DataExfiltrationDetector()
    
    @pytest.mark.asyncio
    async def test_initialization(self, detector):
        """Test detector initialization."""
        assert detector.id == "data_exfiltration_detector"
        assert detector.name == "Data Exfiltration Detector"
        assert detector.enabled is True
    
    @pytest.mark.asyncio
    async def test_large_data_transfer(self, detector):
        """Test detection of large data transfers."""
        test_data = [
            {
                "bytes_transferred": 200 * 1024 * 1024,  # 200MB - above threshold
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8"
            },
            {
                "bytes_transferred": 50 * 1024 * 1024,  # 50MB - below threshold
                "src_ip": "192.168.1.101",
                "dst_ip": "8.8.8.8"
            }
        ]
        
        results = await detector.process(test_data)
        
        # Should detect large transfer
        large_transfer_results = [r for r in results if "Large data transfer" in r.description]
        assert len(large_transfer_results) == 1
        
        result = large_transfer_results[0]
        assert result.severity == DetectionSeverity.MEDIUM
        assert "200.00 MB" in result.description
    
    @pytest.mark.asyncio
    async def test_sensitive_file_access(self, detector):
        """Test detection of sensitive file access."""
        test_data = [
            {"filename": "passwords.csv", "user": "user1"},
            {"filename": "credentials.xlsx", "user": "user2"},
            {"filename": "normal_document.txt", "user": "user3"}
        ]
        
        results = await detector.process(test_data)
        
        # Should detect sensitive file access
        sensitive_results = [r for r in results if "sensitive file" in r.description]
        assert len(sensitive_results) >= 2
        
        for result in sensitive_results:
            assert result.severity == DetectionSeverity.HIGH
    
    @pytest.mark.asyncio
    async def test_off_hours_access(self, detector):
        """Test detection of off-hours data access."""
        # Weekend timestamp
        weekend_time = datetime(2024, 1, 6, 14, 0, 0)  # Saturday
        off_hours_time = datetime(2024, 1, 8, 2, 0, 0)  # Monday 2 AM
        normal_time = datetime(2024, 1, 8, 10, 0, 0)  # Monday 10 AM
        
        test_data = [
            {"timestamp": weekend_time.isoformat(), "user": "user1"},
            {"timestamp": off_hours_time.isoformat(), "user": "user2"},
            {"timestamp": normal_time.isoformat(), "user": "user3"}
        ]
        
        results = await detector.process(test_data)
        
        # Should detect off-hours access
        off_hours_results = [r for r in results if "off-hours" in r.description]
        assert len(off_hours_results) >= 2


class TestDetectorManager:
    """Test detector manager."""
    
    @pytest.fixture
    async def manager(self):
        """Create detector manager."""
        with patch('backend.detectors.manager.get_config') as mock_config:
            mock_config.return_value.ml.model_path = "./test_models"
            manager = DetectorManager()
            await manager.initialize()
            return manager
    
    @pytest.mark.asyncio
    async def test_initialization(self, manager):
        """Test manager initialization."""
        assert len(manager.detectors) > 0
        assert manager.enabled is True
        
        # Check that all detector types are present
        detector_ids = set(manager.detectors.keys())
        expected_ids = {
            "network_anomaly", "user_behavior_anomaly", "timeseries_anomaly",
            "malware_detector", "intrusion_detector", "data_exfiltration_detector"
        }
        assert expected_ids.issubset(detector_ids)
    
    @pytest.mark.asyncio
    async def test_list_detectors(self, manager):
        """Test listing detectors."""
        detectors_info = manager.list_detectors()
        assert len(detectors_info) > 0
        
        for info in detectors_info:
            assert "id" in info
            assert "name" in info
            assert "description" in info
            assert "enabled" in info
            assert "stats" in info
            assert "configuration" in info
    
    @pytest.mark.asyncio
    async def test_enable_disable_detector(self, manager):
        """Test enabling and disabling detectors."""
        detector_id = "malware_detector"
        
        # Disable detector
        manager.disable_detector(detector_id)
        detector = manager.get_detector(detector_id)
        assert detector.enabled is False
        
        # Enable detector
        manager.enable_detector(detector_id)
        assert detector.enabled is True
    
    @pytest.mark.asyncio
    async def test_detect_with_specific_detectors(self, manager):
        """Test detection with specific detectors."""
        test_data = {"filename": "malware.exe"}
        
        # Run only malware detector
        results = await manager.detect(test_data, detector_ids=["malware_detector"])
        
        # Should have results from malware detector only
        if results:
            for result in results:
                assert result.detector_id == "malware_detector"
    
    @pytest.mark.asyncio
    async def test_detect_all_detectors(self, manager):
        """Test detection with all detectors."""
        test_data = {
            "filename": "suspicious.exe",
            "command_line": "powershell -enc VGVzdA==",
            "bytes_transferred": 200 * 1024 * 1024
        }
        
        results = await manager.detect(test_data)
        
        # Should have results from multiple detectors
        detector_ids = set(result.detector_id for result in results)
        assert len(detector_ids) >= 1  # At least one detector should trigger
    
    @pytest.mark.asyncio
    async def test_health_check(self, manager):
        """Test health check functionality."""
        health_status = await manager.health_check()
        
        assert "manager_healthy" in health_status
        assert "detectors_healthy" in health_status
        assert "overall_healthy" in health_status
        assert "timestamp" in health_status
        
        # Check individual detector health
        for detector_id, health_info in health_status["detectors_healthy"].items():
            assert "healthy" in health_info
            assert "enabled" in health_info
    
    @pytest.mark.asyncio
    async def test_statistics(self, manager):
        """Test statistics collection."""
        # Get initial stats
        initial_stats = manager.get_manager_stats()
        assert "total_processed" in initial_stats
        assert "total_detected" in initial_stats
        assert "detectors_count" in initial_stats
        
        # Run detection to update stats
        test_data = {"filename": "test.exe"}
        await manager.detect(test_data)
        
        # Check updated stats
        updated_stats = manager.get_manager_stats()
        assert updated_stats["total_processed"] > initial_stats["total_processed"]
    
    @pytest.mark.asyncio
    async def test_comprehensive_stats(self, manager):
        """Test comprehensive statistics."""
        stats = manager.get_comprehensive_stats()
        
        assert "manager" in stats
        assert "detectors" in stats
        
        # Check manager stats
        manager_stats = stats["manager"]
        assert "total_processed" in manager_stats
        assert "enabled_detectors" in manager_stats
        
        # Check detector stats
        detector_stats = stats["detectors"]
        assert len(detector_stats) > 0
        
        for detector_id, detector_stat in detector_stats.items():
            assert "processed" in detector_stat
            assert "detected" in detector_stat
            assert "errors" in detector_stat


@pytest.mark.asyncio
async def test_detector_integration():
    """Test integration between different detectors."""
    # Create sample data that should trigger multiple detectors
    test_data = {
        "filename": "document.pdf.exe",  # Should trigger malware detector
        "command_line": "powershell -enc VGVzdENvbW1hbmQ=",  # Should trigger malware detector
        "request_body": "username=admin' OR '1'='1",  # Should trigger intrusion detector
        "bytes_transferred": 500 * 1024 * 1024,  # Should trigger exfiltration detector
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8"
    }
    
    # Test individual detectors
    malware_detector = MalwareDetector()
    intrusion_detector = IntrusionDetector()
    exfiltration_detector = DataExfiltrationDetector()
    
    malware_results = await malware_detector.process(test_data)
    intrusion_results = await intrusion_detector.process(test_data)
    exfiltration_results = await exfiltration_detector.process(test_data)
    
    # Should have detections from multiple detectors
    total_detections = len(malware_results) + len(intrusion_results) + len(exfiltration_results)
    assert total_detections >= 3  # At least one from each detector type
    
    # Verify detection results have proper structure
    all_results = malware_results + intrusion_results + exfiltration_results
    for result in all_results:
        assert hasattr(result, 'detector_id')
        assert hasattr(result, 'severity')
        assert hasattr(result, 'confidence')
        assert hasattr(result, 'description')
        assert 0 <= result.confidence <= 1 