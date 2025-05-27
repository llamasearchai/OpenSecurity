"""Detector manager for orchestrating security detectors."""

import asyncio
from typing import Dict, Any, List, Optional, Type
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from backend.detectors.base import BaseDetector, DetectionResult
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
from backend.core.config import get_config
from backend.core.logging import get_logger


class DetectorManager:
    """Manages all security detectors and orchestrates detection operations."""
    
    def __init__(self):
        self.logger = get_logger("detector_manager")
        self.config = get_config()
        self.detectors: Dict[str, BaseDetector] = {}
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.enabled = True
        self.stats = {
            "total_processed": 0,
            "total_detected": 0,
            "total_errors": 0,
            "detectors_count": 0
        }
    
    async def initialize(self) -> None:
        """Initialize all detectors."""
        try:
            self.logger.info("Initializing detector manager")
            
            # Initialize ML-based detectors
            await self._initialize_ml_detectors()
            
            # Initialize rule-based detectors
            await self._initialize_rule_detectors()
            
            self.stats["detectors_count"] = len(self.detectors)
            self.logger.info(f"Initialized {len(self.detectors)} detectors")
            
        except Exception as e:
            self.logger.error(f"Error initializing detector manager: {e}")
            raise
    
    async def _initialize_ml_detectors(self) -> None:
        """Initialize machine learning based detectors."""
        try:
            model_path = self.config.ml.model_path
            
            # Network anomaly detector
            network_detector = NetworkAnomalyDetector(model_path)
            await network_detector.load_model()
            self.detectors[network_detector.id] = network_detector
            
            # User behavior anomaly detector
            user_detector = UserBehaviorAnomalyDetector(model_path)
            await user_detector.load_model()
            self.detectors[user_detector.id] = user_detector
            
            # Time series anomaly detector
            timeseries_detector = TimeSeriesAnomalyDetector(model_path)
            await timeseries_detector.load_model()
            self.detectors[timeseries_detector.id] = timeseries_detector
            
            self.logger.info("ML detectors initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing ML detectors: {e}")
            raise
    
    async def _initialize_rule_detectors(self) -> None:
        """Initialize rule-based detectors."""
        try:
            # Malware detector
            malware_detector = MalwareDetector()
            self.detectors[malware_detector.id] = malware_detector
            
            # Intrusion detector
            intrusion_detector = IntrusionDetector()
            self.detectors[intrusion_detector.id] = intrusion_detector
            
            # Data exfiltration detector
            exfiltration_detector = DataExfiltrationDetector()
            self.detectors[exfiltration_detector.id] = exfiltration_detector
            
            self.logger.info("Rule-based detectors initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing rule detectors: {e}")
            raise
    
    async def detect(self, data: Any, detector_ids: Optional[List[str]] = None) -> List[DetectionResult]:
        """Run detection on data using specified or all detectors."""
        if not self.enabled:
            return []
        
        try:
            self.stats["total_processed"] += 1
            
            # Determine which detectors to use
            if detector_ids:
                detectors_to_use = {
                    id: detector for id, detector in self.detectors.items()
                    if id in detector_ids and detector.enabled
                }
            else:
                detectors_to_use = {
                    id: detector for id, detector in self.detectors.items()
                    if detector.enabled
                }
            
            if not detectors_to_use:
                self.logger.warning("No enabled detectors available")
                return []
            
            # Run detectors concurrently
            tasks = []
            for detector_id, detector in detectors_to_use.items():
                task = asyncio.create_task(
                    self._run_detector_safely(detector, data),
                    name=f"detector_{detector_id}"
                )
                tasks.append(task)
            
            # Wait for all detectors to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect all detection results
            all_detections = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    detector_id = list(detectors_to_use.keys())[i]
                    self.logger.error(f"Detector {detector_id} failed: {result}")
                    self.stats["total_errors"] += 1
                elif isinstance(result, list):
                    all_detections.extend(result)
                    self.stats["total_detected"] += len(result)
            
            # Sort results by severity and confidence
            all_detections.sort(
                key=lambda x: (x.severity.value, x.confidence),
                reverse=True
            )
            
            self.logger.info(f"Detection completed: {len(all_detections)} threats detected")
            return all_detections
            
        except Exception as e:
            self.stats["total_errors"] += 1
            self.logger.error(f"Error during detection: {e}")
            raise
    
    async def _run_detector_safely(self, detector: BaseDetector, data: Any) -> List[DetectionResult]:
        """Run a detector with error handling."""
        try:
            return await detector.process(data)
        except Exception as e:
            self.logger.error(f"Detector {detector.id} failed: {e}")
            return []
    
    async def train_detector(self, detector_id: str, training_data: Any) -> None:
        """Train a specific detector."""
        if detector_id not in self.detectors:
            raise ValueError(f"Detector {detector_id} not found")
        
        try:
            detector = self.detectors[detector_id]
            await detector.train(training_data)
            
            # Save ML models if applicable
            if hasattr(detector, 'save_model'):
                await detector.save_model()
            
            self.logger.info(f"Detector {detector_id} trained successfully")
            
        except Exception as e:
            self.logger.error(f"Error training detector {detector_id}: {e}")
            raise
    
    async def train_all_detectors(self, training_data: Dict[str, Any]) -> None:
        """Train all detectors with appropriate data."""
        try:
            tasks = []
            for detector_id, detector in self.detectors.items():
                if detector_id in training_data:
                    task = asyncio.create_task(
                        self._train_detector_safely(detector, training_data[detector_id]),
                        name=f"train_{detector_id}"
                    )
                    tasks.append(task)
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
                self.logger.info("All detectors training completed")
            
        except Exception as e:
            self.logger.error(f"Error training detectors: {e}")
            raise
    
    async def _train_detector_safely(self, detector: BaseDetector, data: Any) -> None:
        """Train a detector with error handling."""
        try:
            await detector.train(data)
            if hasattr(detector, 'save_model'):
                await detector.save_model()
        except Exception as e:
            self.logger.error(f"Training failed for detector {detector.id}: {e}")
    
    def get_detector(self, detector_id: str) -> Optional[BaseDetector]:
        """Get a specific detector by ID."""
        return self.detectors.get(detector_id)
    
    def list_detectors(self) -> List[Dict[str, Any]]:
        """List all available detectors with their status."""
        detectors_info = []
        for detector_id, detector in self.detectors.items():
            info = {
                "id": detector_id,
                "name": detector.name,
                "description": detector.description,
                "enabled": detector.enabled,
                "stats": detector.get_stats(),
                "configuration": detector.get_configuration()
            }
            detectors_info.append(info)
        
        return detectors_info
    
    def enable_detector(self, detector_id: str) -> None:
        """Enable a specific detector."""
        if detector_id not in self.detectors:
            raise ValueError(f"Detector {detector_id} not found")
        
        self.detectors[detector_id].enable()
        self.logger.info(f"Detector {detector_id} enabled")
    
    def disable_detector(self, detector_id: str) -> None:
        """Disable a specific detector."""
        if detector_id not in self.detectors:
            raise ValueError(f"Detector {detector_id} not found")
        
        self.detectors[detector_id].disable()
        self.logger.info(f"Detector {detector_id} disabled")
    
    def configure_detector(self, detector_id: str, config: Dict[str, Any]) -> None:
        """Configure a specific detector."""
        if detector_id not in self.detectors:
            raise ValueError(f"Detector {detector_id} not found")
        
        try:
            self.detectors[detector_id].set_configuration(config)
            self.logger.info(f"Detector {detector_id} configured successfully")
        except Exception as e:
            self.logger.error(f"Error configuring detector {detector_id}: {e}")
            raise
    
    def reset_detector_stats(self, detector_id: str) -> None:
        """Reset statistics for a specific detector."""
        if detector_id not in self.detectors:
            raise ValueError(f"Detector {detector_id} not found")
        
        self.detectors[detector_id].reset_stats()
        self.logger.info(f"Stats reset for detector {detector_id}")
    
    def reset_all_stats(self) -> None:
        """Reset statistics for all detectors and manager."""
        for detector in self.detectors.values():
            detector.reset_stats()
        
        self.stats = {
            "total_processed": 0,
            "total_detected": 0,
            "total_errors": 0,
            "detectors_count": len(self.detectors)
        }
        
        self.logger.info("All statistics reset")
    
    def get_manager_stats(self) -> Dict[str, Any]:
        """Get manager-level statistics."""
        enabled_count = sum(1 for d in self.detectors.values() if d.enabled)
        
        return {
            **self.stats,
            "enabled_detectors": enabled_count,
            "disabled_detectors": len(self.detectors) - enabled_count,
            "manager_enabled": self.enabled
        }
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive statistics for all detectors."""
        stats = {
            "manager": self.get_manager_stats(),
            "detectors": {}
        }
        
        for detector_id, detector in self.detectors.items():
            stats["detectors"][detector_id] = detector.get_stats()
        
        return stats
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all detectors."""
        health_status = {
            "manager_healthy": True,
            "detectors_healthy": {},
            "overall_healthy": True,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        try:
            # Check each detector
            for detector_id, detector in self.detectors.items():
                detector_healthy = True
                error_message = None
                
                try:
                    # Basic health check - ensure detector can process empty data
                    await detector.process([])
                except Exception as e:
                    detector_healthy = False
                    error_message = str(e)
                
                health_status["detectors_healthy"][detector_id] = {
                    "healthy": detector_healthy,
                    "enabled": detector.enabled,
                    "error": error_message
                }
                
                if not detector_healthy:
                    health_status["overall_healthy"] = False
            
        except Exception as e:
            health_status["manager_healthy"] = False
            health_status["overall_healthy"] = False
            health_status["error"] = str(e)
        
        return health_status
    
    def enable_manager(self) -> None:
        """Enable the detector manager."""
        self.enabled = True
        self.logger.info("Detector manager enabled")
    
    def disable_manager(self) -> None:
        """Disable the detector manager."""
        self.enabled = False
        self.logger.info("Detector manager disabled")
    
    async def shutdown(self) -> None:
        """Shutdown the detector manager and cleanup resources."""
        try:
            self.logger.info("Shutting down detector manager")
            
            # Save all ML models
            save_tasks = []
            for detector in self.detectors.values():
                if hasattr(detector, 'save_model'):
                    task = asyncio.create_task(detector.save_model())
                    save_tasks.append(task)
            
            if save_tasks:
                await asyncio.gather(*save_tasks, return_exceptions=True)
            
            # Shutdown executor
            self.executor.shutdown(wait=True)
            
            self.logger.info("Detector manager shutdown completed")
            
        except Exception as e:
            self.logger.error(f"Error during detector manager shutdown: {e}")


# Global detector manager instance
_detector_manager: Optional[DetectorManager] = None


async def get_detector_manager() -> DetectorManager:
    """Get the global detector manager instance."""
    global _detector_manager
    
    if _detector_manager is None:
        _detector_manager = DetectorManager()
        await _detector_manager.initialize()
    
    return _detector_manager


async def shutdown_detector_manager() -> None:
    """Shutdown the global detector manager."""
    global _detector_manager
    
    if _detector_manager is not None:
        await _detector_manager.shutdown()
        _detector_manager = None 