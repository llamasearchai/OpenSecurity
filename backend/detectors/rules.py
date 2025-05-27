"""Rule-based security detectors for threat detection."""

import re
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Pattern
from dataclasses import dataclass

from backend.detectors.base import BaseDetector, DetectionResult, DetectionSeverity
from backend.core.logging import get_logger


@dataclass
class Rule:
    """Represents a detection rule."""
    id: str
    name: str
    description: str
    severity: DetectionSeverity
    pattern: Optional[Pattern] = None
    conditions: Optional[Dict[str, Any]] = None
    tags: List[str] = None
    tactics: List[str] = None
    techniques: List[str] = None
    enabled: bool = True


class MalwareDetector(BaseDetector):
    """Detects malware indicators and suspicious file patterns."""
    
    def __init__(self):
        super().__init__(
            id="malware_detector",
            name="Malware Detector",
            description="Detects malware signatures and suspicious file patterns"
        )
        self.rules = self._load_malware_rules()
        self.known_malware_hashes = set()
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.js',
            '.jar', '.ps1', '.psm1', '.dll', '.sys', '.drv'
        }
    
    def _load_malware_rules(self) -> List[Rule]:
        """Load malware detection rules."""
        return [
            Rule(
                id="suspicious_file_extension",
                name="Suspicious File Extension",
                description="File with potentially dangerous extension",
                severity=DetectionSeverity.MEDIUM,
                tags=["malware", "file", "extension"],
                tactics=["Initial Access", "Execution"],
                techniques=["T1566", "T1204"]
            ),
            Rule(
                id="double_extension",
                name="Double File Extension",
                description="File with double extension (e.g., .pdf.exe)",
                severity=DetectionSeverity.HIGH,
                pattern=re.compile(r'\.[a-zA-Z0-9]{2,4}\.(exe|scr|bat|cmd|com|pif)$', re.IGNORECASE),
                tags=["malware", "file", "social_engineering"],
                tactics=["Initial Access"],
                techniques=["T1566.001"]
            ),
            Rule(
                id="powershell_encoded_command",
                name="PowerShell Encoded Command",
                description="PowerShell command with base64 encoding",
                severity=DetectionSeverity.HIGH,
                pattern=re.compile(r'powershell.*-enc.*[A-Za-z0-9+/]{20,}', re.IGNORECASE),
                tags=["powershell", "encoded", "command"],
                tactics=["Execution", "Defense Evasion"],
                techniques=["T1059.001", "T1027"]
            ),
            Rule(
                id="suspicious_registry_modification",
                name="Suspicious Registry Modification",
                description="Modification to critical registry keys",
                severity=DetectionSeverity.HIGH,
                pattern=re.compile(r'(HKLM|HKCU)\\(SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|SYSTEM\\CurrentControlSet\\Services)', re.IGNORECASE),
                tags=["registry", "persistence"],
                tactics=["Persistence"],
                techniques=["T1547.001"]
            ),
            Rule(
                id="suspicious_network_connection",
                name="Suspicious Network Connection",
                description="Connection to known malicious IP or domain",
                severity=DetectionSeverity.CRITICAL,
                tags=["network", "c2", "malicious"],
                tactics=["Command and Control"],
                techniques=["T1071"]
            )
        ]
    
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process data for malware indicators."""
        if not self.enabled:
            return []
        
        try:
            self.last_run = datetime.utcnow()
            self.stats["processed"] += 1
            
            if not isinstance(data, list):
                data = [data]
            
            results = []
            for item in data:
                for rule in self.rules:
                    if not rule.enabled:
                        continue
                    
                    detection = self._apply_rule(rule, item)
                    if detection:
                        results.append(detection)
                        self.stats["detected"] += 1
            
            return results
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing malware detection: {e}")
            raise
    
    def _apply_rule(self, rule: Rule, data: Dict[str, Any]) -> Optional[DetectionResult]:
        """Apply a specific rule to data."""
        try:
            if rule.id == "suspicious_file_extension":
                filename = data.get('filename', '')
                if any(filename.lower().endswith(ext) for ext in self.suspicious_extensions):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.7,
                        description=f"Suspicious file extension detected: {filename}",
                        raw_data=data,
                        entities=[filename],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "filename": filename}
                    )
            
            elif rule.id == "double_extension" and rule.pattern:
                filename = data.get('filename', '')
                if rule.pattern.search(filename):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.9,
                        description=f"Double file extension detected: {filename}",
                        raw_data=data,
                        entities=[filename],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "filename": filename}
                    )
            
            elif rule.id == "powershell_encoded_command" and rule.pattern:
                command = data.get('command_line', '')
                if rule.pattern.search(command):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.8,
                        description="PowerShell encoded command detected",
                        raw_data=data,
                        entities=[data.get('process_name', '')],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "command": command}
                    )
            
            elif rule.id == "suspicious_registry_modification" and rule.pattern:
                registry_key = data.get('registry_key', '')
                if rule.pattern.search(registry_key):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.8,
                        description=f"Suspicious registry modification: {registry_key}",
                        raw_data=data,
                        entities=[registry_key],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "registry_key": registry_key}
                    )
            
            elif rule.id == "suspicious_network_connection":
                dst_ip = data.get('dst_ip', '')
                dst_domain = data.get('dst_domain', '')
                if self._is_suspicious_destination(dst_ip, dst_domain):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.9,
                        description=f"Connection to suspicious destination: {dst_ip or dst_domain}",
                        raw_data=data,
                        entities=[dst_ip, dst_domain],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "destination": dst_ip or dst_domain}
                    )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error applying rule {rule.id}: {e}")
            return None
    
    def _is_suspicious_destination(self, ip: str, domain: str) -> bool:
        """Check if destination is suspicious."""
        # Check for suspicious domains
        suspicious_domains = [
            'tempuri.org', 'bit.ly', 'tinyurl.com', 'pastebin.com',
            'hastebin.com', 'discord.gg', 'telegram.me'
        ]
        
        if domain and any(susp in domain.lower() for susp in suspicious_domains):
            return True
        
        # Check for suspicious IP ranges (example: Tor exit nodes, known malicious ranges)
        if ip:
            try:
                ip_obj = ipaddress.ip_address(ip)
                # Example: Check for private IPs being contacted from internal networks
                if ip_obj.is_private and not ip_obj.is_loopback:
                    return False  # Internal traffic, not suspicious
                # Add more sophisticated IP reputation checks here
            except ValueError:
                pass
        
        return False
    
    async def train(self, training_data: Any) -> None:
        """Update malware signatures and rules."""
        try:
            if isinstance(training_data, dict):
                # Update known malware hashes
                if 'malware_hashes' in training_data:
                    self.known_malware_hashes.update(training_data['malware_hashes'])
                
                # Update suspicious domains/IPs
                if 'suspicious_domains' in training_data:
                    # Add to internal blacklist
                    pass
                
            self.logger.info("Malware detector training completed")
            
        except Exception as e:
            self.logger.error(f"Error training malware detector: {e}")
            raise
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "rules_count": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "known_hashes_count": len(self.known_malware_hashes),
            "suspicious_extensions": list(self.suspicious_extensions)
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        if "suspicious_extensions" in config:
            self.suspicious_extensions = set(config["suspicious_extensions"])


class IntrusionDetector(BaseDetector):
    """Detects intrusion attempts and suspicious activities."""
    
    def __init__(self):
        super().__init__(
            id="intrusion_detector",
            name="Intrusion Detector",
            description="Detects intrusion attempts and suspicious network activities"
        )
        self.rules = self._load_intrusion_rules()
        self.failed_login_threshold = 5
        self.time_window = timedelta(minutes=15)
        self.failed_attempts = {}
    
    def _load_intrusion_rules(self) -> List[Rule]:
        """Load intrusion detection rules."""
        return [
            Rule(
                id="brute_force_login",
                name="Brute Force Login Attempt",
                description="Multiple failed login attempts from same source",
                severity=DetectionSeverity.HIGH,
                tags=["brute_force", "login", "authentication"],
                tactics=["Credential Access"],
                techniques=["T1110"]
            ),
            Rule(
                id="port_scan",
                name="Port Scan Detection",
                description="Multiple connection attempts to different ports",
                severity=DetectionSeverity.MEDIUM,
                tags=["port_scan", "reconnaissance"],
                tactics=["Discovery"],
                techniques=["T1046"]
            ),
            Rule(
                id="sql_injection",
                name="SQL Injection Attempt",
                description="Potential SQL injection in web request",
                severity=DetectionSeverity.HIGH,
                pattern=re.compile(r"('|(\\')|(;)|(\\;))|(\\x27)|(\\x2D\\x2D)|(\\')|(\\\")|(\\x22)|(\\x2A)|(\\x2F)|(\\x5C)", re.IGNORECASE),
                tags=["sql_injection", "web", "injection"],
                tactics=["Initial Access"],
                techniques=["T1190"]
            ),
            Rule(
                id="xss_attempt",
                name="Cross-Site Scripting Attempt",
                description="Potential XSS attack in web request",
                severity=DetectionSeverity.MEDIUM,
                pattern=re.compile(r'<script[^>]*>.*?</script>|javascript:|on\w+\s*=', re.IGNORECASE),
                tags=["xss", "web", "injection"],
                tactics=["Initial Access"],
                techniques=["T1190"]
            ),
            Rule(
                id="privilege_escalation",
                name="Privilege Escalation Attempt",
                description="Attempt to escalate privileges",
                severity=DetectionSeverity.CRITICAL,
                pattern=re.compile(r'(sudo|su|runas|net user.*admin|whoami /priv)', re.IGNORECASE),
                tags=["privilege_escalation", "command"],
                tactics=["Privilege Escalation"],
                techniques=["T1548"]
            )
        ]
    
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process data for intrusion indicators."""
        if not self.enabled:
            return []
        
        try:
            self.last_run = datetime.utcnow()
            self.stats["processed"] += 1
            
            if not isinstance(data, list):
                data = [data]
            
            results = []
            for item in data:
                for rule in self.rules:
                    if not rule.enabled:
                        continue
                    
                    detection = self._apply_intrusion_rule(rule, item)
                    if detection:
                        results.append(detection)
                        self.stats["detected"] += 1
            
            return results
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing intrusion detection: {e}")
            raise
    
    def _apply_intrusion_rule(self, rule: Rule, data: Dict[str, Any]) -> Optional[DetectionResult]:
        """Apply intrusion detection rule."""
        try:
            if rule.id == "brute_force_login":
                return self._detect_brute_force(data)
            
            elif rule.id == "port_scan":
                return self._detect_port_scan(data)
            
            elif rule.id == "sql_injection" and rule.pattern:
                request_data = data.get('request_body', '') + data.get('url_params', '')
                if rule.pattern.search(request_data):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.8,
                        description="SQL injection attempt detected",
                        raw_data=data,
                        entities=[data.get('src_ip', ''), data.get('url', '')],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "request_data": request_data[:200]}
                    )
            
            elif rule.id == "xss_attempt" and rule.pattern:
                request_data = data.get('request_body', '') + data.get('url_params', '')
                if rule.pattern.search(request_data):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.7,
                        description="XSS attempt detected",
                        raw_data=data,
                        entities=[data.get('src_ip', ''), data.get('url', '')],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "request_data": request_data[:200]}
                    )
            
            elif rule.id == "privilege_escalation" and rule.pattern:
                command = data.get('command_line', '')
                if rule.pattern.search(command):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.9,
                        description="Privilege escalation attempt detected",
                        raw_data=data,
                        entities=[data.get('user', ''), data.get('process_name', '')],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "command": command}
                    )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error applying intrusion rule {rule.id}: {e}")
            return None
    
    def _detect_brute_force(self, data: Dict[str, Any]) -> Optional[DetectionResult]:
        """Detect brute force login attempts."""
        if data.get('event_type') != 'login_failed':
            return None
        
        src_ip = data.get('src_ip', '')
        if not src_ip:
            return None
        
        current_time = datetime.utcnow()
        
        # Clean old entries
        self._cleanup_failed_attempts(current_time)
        
        # Track failed attempt
        if src_ip not in self.failed_attempts:
            self.failed_attempts[src_ip] = []
        
        self.failed_attempts[src_ip].append(current_time)
        
        # Check if threshold exceeded
        recent_attempts = [
            t for t in self.failed_attempts[src_ip]
            if current_time - t <= self.time_window
        ]
        
        if len(recent_attempts) >= self.failed_login_threshold:
            return DetectionResult(
                detector_id=self.id,
                detector_name=self.name,
                severity=DetectionSeverity.HIGH,
                confidence=0.9,
                description=f"Brute force attack detected from {src_ip}",
                raw_data=data,
                entities=[src_ip, data.get('username', '')],
                tactics=["Credential Access"],
                techniques=["T1110"],
                tags=["brute_force", "login", "authentication"],
                metadata={
                    "rule_id": "brute_force_login",
                    "failed_attempts": len(recent_attempts),
                    "time_window_minutes": self.time_window.total_seconds() / 60
                }
            )
        
        return None
    
    def _detect_port_scan(self, data: Dict[str, Any]) -> Optional[DetectionResult]:
        """Detect port scanning activity."""
        # This would require maintaining state of connection attempts
        # Simplified implementation for demonstration
        src_ip = data.get('src_ip', '')
        dst_port = data.get('dst_port', 0)
        
        if src_ip and dst_port:
            # In a real implementation, you'd track unique ports per source IP
            # and detect when threshold is exceeded
            pass
        
        return None
    
    def _cleanup_failed_attempts(self, current_time: datetime) -> None:
        """Clean up old failed login attempts."""
        cutoff_time = current_time - self.time_window
        
        for src_ip in list(self.failed_attempts.keys()):
            self.failed_attempts[src_ip] = [
                t for t in self.failed_attempts[src_ip]
                if t > cutoff_time
            ]
            
            if not self.failed_attempts[src_ip]:
                del self.failed_attempts[src_ip]
    
    async def train(self, training_data: Any) -> None:
        """Update intrusion detection rules and thresholds."""
        try:
            if isinstance(training_data, dict):
                if 'failed_login_threshold' in training_data:
                    self.failed_login_threshold = training_data['failed_login_threshold']
                
                if 'time_window_minutes' in training_data:
                    self.time_window = timedelta(minutes=training_data['time_window_minutes'])
            
            self.logger.info("Intrusion detector training completed")
            
        except Exception as e:
            self.logger.error(f"Error training intrusion detector: {e}")
            raise
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "rules_count": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "failed_login_threshold": self.failed_login_threshold,
            "time_window_minutes": self.time_window.total_seconds() / 60,
            "tracked_ips": len(self.failed_attempts)
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        if "failed_login_threshold" in config:
            self.failed_login_threshold = config["failed_login_threshold"]
        if "time_window_minutes" in config:
            self.time_window = timedelta(minutes=config["time_window_minutes"])


class DataExfiltrationDetector(BaseDetector):
    """Detects potential data exfiltration activities."""
    
    def __init__(self):
        super().__init__(
            id="data_exfiltration_detector",
            name="Data Exfiltration Detector",
            description="Detects potential data exfiltration and unauthorized data access"
        )
        self.rules = self._load_exfiltration_rules()
        self.data_transfer_threshold = 100 * 1024 * 1024  # 100MB
        self.sensitive_file_patterns = [
            r'.*\.csv$', r'.*\.xlsx?$', r'.*\.pdf$', r'.*\.doc[x]?$',
            r'.*password.*', r'.*credential.*', r'.*secret.*', r'.*key.*'
        ]
    
    def _load_exfiltration_rules(self) -> List[Rule]:
        """Load data exfiltration detection rules."""
        return [
            Rule(
                id="large_data_transfer",
                name="Large Data Transfer",
                description="Unusually large data transfer detected",
                severity=DetectionSeverity.MEDIUM,
                tags=["data_transfer", "exfiltration"],
                tactics=["Exfiltration"],
                techniques=["T1041"]
            ),
            Rule(
                id="sensitive_file_access",
                name="Sensitive File Access",
                description="Access to sensitive files detected",
                severity=DetectionSeverity.HIGH,
                tags=["file_access", "sensitive_data"],
                tactics=["Collection"],
                techniques=["T1005"]
            ),
            Rule(
                id="off_hours_data_access",
                name="Off-Hours Data Access",
                description="Data access during off-hours",
                severity=DetectionSeverity.MEDIUM,
                tags=["off_hours", "data_access"],
                tactics=["Collection"],
                techniques=["T1005"]
            ),
            Rule(
                id="external_data_transfer",
                name="External Data Transfer",
                description="Data transfer to external destination",
                severity=DetectionSeverity.HIGH,
                tags=["external_transfer", "exfiltration"],
                tactics=["Exfiltration"],
                techniques=["T1041"]
            )
        ]
    
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process data for exfiltration indicators."""
        if not self.enabled:
            return []
        
        try:
            self.last_run = datetime.utcnow()
            self.stats["processed"] += 1
            
            if not isinstance(data, list):
                data = [data]
            
            results = []
            for item in data:
                for rule in self.rules:
                    if not rule.enabled:
                        continue
                    
                    detection = self._apply_exfiltration_rule(rule, item)
                    if detection:
                        results.append(detection)
                        self.stats["detected"] += 1
            
            return results
            
        except Exception as e:
            self.stats["errors"] += 1
            self.logger.error(f"Error processing data exfiltration detection: {e}")
            raise
    
    def _apply_exfiltration_rule(self, rule: Rule, data: Dict[str, Any]) -> Optional[DetectionResult]:
        """Apply data exfiltration rule."""
        try:
            if rule.id == "large_data_transfer":
                bytes_transferred = data.get('bytes_transferred', 0)
                if bytes_transferred > self.data_transfer_threshold:
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.7,
                        description=f"Large data transfer detected: {bytes_transferred / (1024*1024):.2f} MB",
                        raw_data=data,
                        entities=[data.get('src_ip', ''), data.get('dst_ip', '')],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={
                            "rule_id": rule.id,
                            "bytes_transferred": bytes_transferred,
                            "threshold_mb": self.data_transfer_threshold / (1024*1024)
                        }
                    )
            
            elif rule.id == "sensitive_file_access":
                filename = data.get('filename', '')
                if any(re.match(pattern, filename, re.IGNORECASE) for pattern in self.sensitive_file_patterns):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.8,
                        description=f"Access to sensitive file: {filename}",
                        raw_data=data,
                        entities=[data.get('user', ''), filename],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "filename": filename}
                    )
            
            elif rule.id == "off_hours_data_access":
                timestamp = data.get('timestamp')
                if timestamp and self._is_off_hours(timestamp):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.6,
                        description="Data access during off-hours detected",
                        raw_data=data,
                        entities=[data.get('user', '')],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "timestamp": timestamp}
                    )
            
            elif rule.id == "external_data_transfer":
                dst_ip = data.get('dst_ip', '')
                if dst_ip and self._is_external_ip(dst_ip):
                    return DetectionResult(
                        detector_id=self.id,
                        detector_name=self.name,
                        severity=rule.severity,
                        confidence=0.8,
                        description=f"Data transfer to external destination: {dst_ip}",
                        raw_data=data,
                        entities=[data.get('src_ip', ''), dst_ip],
                        tactics=rule.tactics,
                        techniques=rule.techniques,
                        tags=rule.tags,
                        metadata={"rule_id": rule.id, "destination": dst_ip}
                    )
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error applying exfiltration rule {rule.id}: {e}")
            return None
    
    def _is_off_hours(self, timestamp: str) -> bool:
        """Check if timestamp is during off-hours."""
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            # Consider off-hours as weekends or outside 9-17 hours
            return dt.weekday() >= 5 or dt.hour < 9 or dt.hour > 17
        except:
            return False
    
    def _is_external_ip(self, ip: str) -> bool:
        """Check if IP is external (not private)."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast)
        except:
            return False
    
    async def train(self, training_data: Any) -> None:
        """Update exfiltration detection parameters."""
        try:
            if isinstance(training_data, dict):
                if 'data_transfer_threshold_mb' in training_data:
                    self.data_transfer_threshold = training_data['data_transfer_threshold_mb'] * 1024 * 1024
                
                if 'sensitive_file_patterns' in training_data:
                    self.sensitive_file_patterns = training_data['sensitive_file_patterns']
            
            self.logger.info("Data exfiltration detector training completed")
            
        except Exception as e:
            self.logger.error(f"Error training data exfiltration detector: {e}")
            raise
    
    def get_configuration(self) -> Dict[str, Any]:
        """Get current configuration."""
        return {
            "rules_count": len(self.rules),
            "enabled_rules": len([r for r in self.rules if r.enabled]),
            "data_transfer_threshold_mb": self.data_transfer_threshold / (1024*1024),
            "sensitive_file_patterns": self.sensitive_file_patterns
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set detector configuration."""
        if "data_transfer_threshold_mb" in config:
            self.data_transfer_threshold = config["data_transfer_threshold_mb"] * 1024 * 1024
        if "sensitive_file_patterns" in config:
            self.sensitive_file_patterns = config["sensitive_file_patterns"] 