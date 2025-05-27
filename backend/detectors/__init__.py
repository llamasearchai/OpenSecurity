"""Security detectors module for threat detection and analysis."""

from backend.detectors.base import (
    BaseDetector,
    MLDetector,
    DetectionResult,
    DetectionSeverity
)

from backend.detectors.anomaly import (
    NetworkAnomalyDetector,
    UserBehaviorAnomalyDetector,
    TimeSeriesAnomalyDetector
)

from backend.detectors.rules import (
    Rule,
    MalwareDetector,
    IntrusionDetector,
    DataExfiltrationDetector
)

from backend.detectors.manager import (
    DetectorManager,
    get_detector_manager,
    shutdown_detector_manager
)

__all__ = [
    # Base classes
    "BaseDetector",
    "MLDetector",
    "DetectionResult",
    "DetectionSeverity",
    
    # Anomaly detectors
    "NetworkAnomalyDetector",
    "UserBehaviorAnomalyDetector", 
    "TimeSeriesAnomalyDetector",
    
    # Rule-based detectors
    "Rule",
    "MalwareDetector",
    "IntrusionDetector",
    "DataExfiltrationDetector",
    
    # Manager
    "DetectorManager",
    "get_detector_manager",
    "shutdown_detector_manager"
] 