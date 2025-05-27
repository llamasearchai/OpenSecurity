"""Base classes for all security detectors."""

import uuid
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field

from backend.core.logging import get_logger


class DetectionSeverity(str, Enum):
    """Detection severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionResult(BaseModel):
    """Model representing a detection result."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    detector_id: str
    detector_name: str
    severity: DetectionSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    raw_data: Dict[str, Any]
    entities: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    techniques: List[str] = Field(default_factory=list)
    alert_triggered: bool = False
    false_positive: bool = False
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return self.dict()


class BaseDetector(ABC):
    """Base class for all security detectors."""
    
    def __init__(self, id: str, name: str, description: str):
        self.id = id
        self.name = name
        self.description = description
        self.logger = get_logger(f"detector.{id}")
        self.enabled = True
        self.last_run = None
        self.stats = {
            "processed": 0,
            "detected": 0,
            "errors": 0,
        }
    
    @abstractmethod
    async def process(self, data: Any) -> List[DetectionResult]:
        """Process data and return detection results."""
        pass
    
    @abstractmethod
    async def train(self, training_data: Any) -> None:
        """Train the detector with provided data."""
        pass
    
    @abstractmethod
    def get_configuration(self) -> Dict[str, Any]:
        """Get the current detector configuration."""
        pass
    
    @abstractmethod
    def set_configuration(self, config: Dict[str, Any]) -> None:
        """Set the detector configuration."""
        pass
    
    def enable(self) -> None:
        """Enable the detector."""
        self.enabled = True
        self.logger.info(f"Detector {self.name} enabled")
    
    def disable(self) -> None:
        """Disable the detector."""
        self.enabled = False
        self.logger.info(f"Detector {self.name} disabled")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get detector statistics."""
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            **self.stats
        }
    
    def reset_stats(self) -> None:
        """Reset detector statistics."""
        self.stats = {
            "processed": 0,
            "detected": 0,
            "errors": 0,
        }
        self.logger.info(f"Stats reset for detector {self.name}")


class MLDetector(BaseDetector):
    """Base class for ML-based detectors."""
    
    def __init__(self, id: str, name: str, description: str, model_path: Optional[str] = None):
        super().__init__(id, name, description)
        self.model_path = model_path
        self.model = None
        self.threshold = 0.7  # Default detection threshold
        
    @abstractmethod
    async def load_model(self) -> None:
        """Load the ML model."""
        pass
    
    @abstractmethod
    async def save_model(self) -> None:
        """Save the current ML model."""
        pass
    
    def set_threshold(self, threshold: float) -> None:
        """Set the detection threshold."""
        if 0.0 <= threshold <= 1.0:
            self.threshold = threshold
            self.logger.info(f"Detection threshold set to {threshold}")
        else:
            self.logger.error(f"Invalid threshold value: {threshold}")
            raise ValueError("Threshold must be between 0.0 and 1.0") 