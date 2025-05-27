"""API routes for security detectors."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel, Field

from backend.core.logging import get_logger
from backend.detectors.base import BaseDetector, DetectionResult
from backend.api.routes.auth import verify_token

router = APIRouter()
logger = get_logger("api.detectors")

# Mock detector registry (in production, use a proper registry)
DETECTORS: Dict[str, BaseDetector] = {}


class DetectorInfo(BaseModel):
    """Detector information model."""
    id: str
    name: str
    description: str
    type: str
    enabled: bool
    stats: Dict[str, Any]


class DetectionRequest(BaseModel):
    """Detection request model."""
    data: Dict[str, Any] = Field(..., description="Data to analyze")
    detector_id: Optional[str] = Field(None, description="Specific detector to use")


class DetectionResponse(BaseModel):
    """Detection response model."""
    detector_id: str
    detector_name: str
    timestamp: str
    detection_count: int
    results: List[Dict[str, Any]]


@router.get("/", response_model=List[DetectorInfo])
async def list_detectors(
    current_user: Dict[str, Any] = Depends(verify_token)
) -> List[DetectorInfo]:
    """List all available detectors."""
    try:
        detectors = []
        for detector_id, detector in DETECTORS.items():
            detectors.append(DetectorInfo(
                id=detector.id,
                name=detector.name,
                description=detector.description,
                type=detector.__class__.__name__,
                enabled=detector.enabled,
                stats=detector.get_stats(),
            ))
        
        return detectors
        
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
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
        
        return DetectorInfo(
            id=detector.id,
            name=detector.name,
            description=detector.description,
            type=detector.__class__.__name__,
            enabled=detector.enabled,
            stats=detector.get_stats(),
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
        if request.detector_id:
            if request.detector_id not in DETECTORS:
                raise HTTPException(status_code=404, detail="Detector not found")
            detectors_to_run = [DETECTORS[request.detector_id]]
        else:
            # Run all enabled detectors
            detectors_to_run = [d for d in DETECTORS.values() if d.enabled]
        
        if not detectors_to_run:
            raise HTTPException(status_code=400, detail="No detectors available")
        
        all_results = []
        detector_name = "Multiple Detectors"
        detector_id = "multiple"
        
        for detector in detectors_to_run:
            try:
                results = await detector.process(request.data)
                all_results.extend([result.to_dict() for result in results])
                
                if len(detectors_to_run) == 1:
                    detector_name = detector.name
                    detector_id = detector.id
                    
            except Exception as e:
                logger.error(f"Error in detector {detector.id}: {str(e)}")
                # Continue with other detectors
        
        return DetectionResponse(
            detector_id=detector_id,
            detector_name=detector_name,
            timestamp=datetime.utcnow().isoformat(),
            detection_count=len(all_results),
            results=all_results,
        )
        
    except HTTPException:
        raise
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
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
        detector.enable()
        
        return {"message": f"Detector {detector_id} enabled"}
        
    except HTTPException:
        raise
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
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
        detector.disable()
        
        return {"message": f"Detector {detector_id} disabled"}
        
    except HTTPException:
        raise
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
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
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
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
        detector.set_configuration(config)
        
        return {"message": f"Detector {detector_id} configuration updated"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating detector config {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{detector_id}/train")
async def train_detector(
    detector_id: str,
    training_data: List[Dict[str, Any]] = Body(...),
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Train a detector with provided data."""
    try:
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
        await detector.train(training_data)
        
        return {"message": f"Detector {detector_id} training completed"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error training detector {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{detector_id}/reset-stats")
async def reset_detector_stats(
    detector_id: str,
    current_user: Dict[str, Any] = Depends(verify_token)
) -> Dict[str, str]:
    """Reset detector statistics."""
    try:
        if detector_id not in DETECTORS:
            raise HTTPException(status_code=404, detail="Detector not found")
        
        detector = DETECTORS[detector_id]
        detector.reset_stats()
        
        return {"message": f"Detector {detector_id} statistics reset"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error resetting detector stats {detector_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 