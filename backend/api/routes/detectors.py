"""API routes for security detectors."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel, Field

from backend.core.logging import get_logger
from backend.detectors.manager import get_detector_manager
from backend.detectors.base import DetectionSeverity
from backend.api.routes.auth import verify_token

router = APIRouter()
logger = get_logger("api.detectors")


class DetectorInfo(BaseModel):
    """Detector information model."""
    id: str
    name: str
    description: str
    type: str
    enabled: bool
    stats: Dict[str, Any]
    configuration: Dict[str, Any]


class DetectionRequest(BaseModel):
    """Detection request model."""
    data: Any = Field(..., description="Data to analyze")
    detector_ids: Optional[List[str]] = Field(None, description="Specific detectors to use")


class DetectionResponse(BaseModel):
    """Detection response model."""
    timestamp: str
    detection_count: int
    detectors_used: List[str]
    results: List[Dict[str, Any]]
    summary: Dict[str, Any]


class TrainingRequest(BaseModel):
    """Training request model."""
    training_data: Any = Field(..., description="Training data")


class HealthCheckResponse(BaseModel):
    """Health check response model."""
    manager_healthy: bool
    detectors_healthy: Dict[str, Dict[str, Any]]
    overall_healthy: bool
    timestamp: str


@router.get("/", response_model=List[DetectorInfo])
async def list_detectors(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> List[DetectorInfo]:
    """List all available detectors."""
    try:
        detector_manager = await get_detector_manager()
        detectors_info = detector_manager.list_detectors()
        
        return [
            DetectorInfo(
                id=info["id"],
                name=info["name"],
                description=info["description"],
                type=info["stats"].get("type", "Unknown"),
                enabled=info["enabled"],
                stats=info["stats"],
                configuration=info["configuration"]
            )
            for info in detectors_info
        ]
        
    except Exception as e:
        logger.error(f"Error listing detectors: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{detector_id}", response_model=DetectorInfo)
async def get_detector(
    detector_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> DetectorInfo:
    """Get detector details by ID."""
    try:
        detector_manager = await get_detector_manager()
        detector = detector_manager.get_detector(detector_id)
        
        if not detector:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        return DetectorInfo(
            id=detector.id,
            name=detector.name,
            description=detector.description,
            type=detector.__class__.__name__,
            enabled=detector.enabled,
            stats=detector.get_stats(),
            configuration=detector.get_configuration()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting detector {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect", response_model=DetectionResponse)
async def run_detection(
    request: DetectionRequest,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> DetectionResponse:
    """Run detection on provided data."""
    try:
        detector_manager = await get_detector_manager()
        
        # Run detection
        results = await detector_manager.detect(
            data=request.data,
            detector_ids=request.detector_ids
        )
        
        # Convert results to dictionaries
        result_dicts = [result.to_dict() for result in results]
        
        # Create summary
        severity_counts = {}
        detectors_used = set()
        
        for result in results:
            severity = result.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            detectors_used.add(result.detector_id)
        
        summary = {
            "severity_breakdown": severity_counts,
            "highest_severity": max([r.severity.value for r in results], default="none"),
            "average_confidence": sum([r.confidence for r in results]) / len(results) if results else 0,
            "unique_detectors": len(detectors_used),
            "total_detections": len(results)
        }
        
        return DetectionResponse(
            timestamp=datetime.utcnow().isoformat(),
            detection_count=len(results),
            detectors_used=list(detectors_used),
            results=result_dicts,
            summary=summary
        )
        
    except Exception as e:
        logger.error(f"Error running detection: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{detector_id}/enable")
async def enable_detector(
    detector_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Enable a detector."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.enable_detector(detector_id)
        
        return {"message": f"Detector {detector_id} enabled"}
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error enabling detector {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{detector_id}/disable")
async def disable_detector(
    detector_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Disable a detector."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.disable_detector(detector_id)
        
        return {"message": f"Detector {detector_id} disabled"}
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error disabling detector {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{detector_id}/config")
async def get_detector_config(
    detector_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Get detector configuration."""
    try:
        detector_manager = await get_detector_manager()
        detector = detector_manager.get_detector(detector_id)
        
        if not detector:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        return detector.get_configuration()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting detector config {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{detector_id}/config")
async def update_detector_config(
    detector_id: str,
    config: Dict[str, Any] = Body(...),
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Update detector configuration."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.configure_detector(detector_id, config)
        
        return {"message": f"Detector {detector_id} configuration updated"}
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error updating detector config {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{detector_id}/train")
async def train_detector(
    detector_id: str,
    request: TrainingRequest,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Train a detector with provided data."""
    try:
        detector_manager = await get_detector_manager()
        await detector_manager.train_detector(detector_id, request.training_data)
        
        return {"message": f"Detector {detector_id} training completed"}
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error training detector {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/train-all")
async def train_all_detectors(
    training_data: Dict[str, Any] = Body(...),
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Train all detectors with provided data."""
    try:
        detector_manager = await get_detector_manager()
        await detector_manager.train_all_detectors(training_data)
        
        return {"message": "All detectors training completed"}
        
    except Exception as e:
        logger.error(f"Error training all detectors: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{detector_id}/reset-stats")
async def reset_detector_stats(
    detector_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Reset detector statistics."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.reset_detector_stats(detector_id)
        
        return {"message": f"Detector {detector_id} statistics reset"}
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error resetting detector stats {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset-all-stats")
async def reset_all_stats(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Reset all detector statistics."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.reset_all_stats()
        
        return {"message": "All detector statistics reset"}
        
    except Exception as e:
        logger.error(f"Error resetting all stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/manager")
async def get_manager_stats(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Get detector manager statistics."""
    try:
        detector_manager = await get_detector_manager()
        return detector_manager.get_manager_stats()
        
    except Exception as e:
        logger.error(f"Error getting manager stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/comprehensive")
async def get_comprehensive_stats(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, Any]:
    """Get comprehensive statistics for all detectors."""
    try:
        detector_manager = await get_detector_manager()
        return detector_manager.get_comprehensive_stats()
        
    except Exception as e:
        logger.error(f"Error getting comprehensive stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health/check", response_model=HealthCheckResponse)
async def health_check(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> HealthCheckResponse:
    """Perform health check on all detectors."""
    try:
        detector_manager = await get_detector_manager()
        health_status = await detector_manager.health_check()
        
        return HealthCheckResponse(**health_status)
        
    except Exception as e:
        logger.error(f"Error performing health check: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/manager/enable")
async def enable_manager(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Enable the detector manager."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.enable_manager()
        
        return {"message": "Detector manager enabled"}
        
    except Exception as e:
        logger.error(f"Error enabling manager: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/manager/disable")
async def disable_manager(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Disable the detector manager."""
    try:
        detector_manager = await get_detector_manager()
        detector_manager.disable_manager()
        
        return {"message": "Detector manager disabled"}
        
    except Exception as e:
        logger.error(f"Error disabling manager: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 