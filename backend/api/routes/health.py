"""Health check API routes."""

import time
import psutil
from typing import Dict, Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from backend.core.config import get_config
from backend.core.logging import get_logger
from backend.agents.manager import get_agent_manager

router = APIRouter()
logger = get_logger("api.health")
config = get_config()


class HealthStatus(BaseModel):
    """Health status model."""
    status: str
    timestamp: float
    version: str
    environment: str
    uptime: float
    system: Dict[str, Any]
    services: Dict[str, Any]


@router.get("/", response_model=HealthStatus)
async def health_check() -> HealthStatus:
    """Comprehensive health check."""
    try:
        start_time = time.time()
        
        # System metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        system_info = {
            "cpu_percent": cpu_percent,
            "memory": {
                "total": memory.total,
                "available": memory.available,
                "percent": memory.percent,
                "used": memory.used,
                "free": memory.free,
            },
            "disk": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
                "percent": (disk.used / disk.total) * 100,
            },
            "load_average": list(psutil.getloadavg()) if hasattr(psutil, 'getloadavg') else None,
        }
        
        # Service health checks
        services = {}
        
        # Check agent manager
        try:
            agent_manager = await get_agent_manager()
            agent_health = await agent_manager.health_check()
            services["agent_manager"] = {
                "status": agent_health.get("manager_status", "unknown"),
                "details": agent_health,
            }
        except Exception as e:
            services["agent_manager"] = {
                "status": "unhealthy",
                "error": str(e),
            }
        
        # Overall status determination
        overall_status = "healthy"
        
        # Check system resources
        if cpu_percent > 90:
            overall_status = "degraded"
        if memory.percent > 90:
            overall_status = "degraded"
        if (disk.used / disk.total) * 100 > 90:
            overall_status = "degraded"
        
        # Check services
        for service_name, service_info in services.items():
            if service_info["status"] not in ["healthy", "degraded"]:
                overall_status = "unhealthy"
                break
            elif service_info["status"] == "degraded" and overall_status == "healthy":
                overall_status = "degraded"
        
        return HealthStatus(
            status=overall_status,
            timestamp=time.time(),
            version=config.api.version,
            environment=config.environment,
            uptime=time.time() - start_time,  # This would be actual uptime in production
            system=system_info,
            services=services,
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Health check failed: {str(e)}")


@router.get("/liveness")
async def liveness_probe() -> Dict[str, str]:
    """Kubernetes liveness probe endpoint."""
    return {"status": "alive", "timestamp": str(time.time())}


@router.get("/readiness")
async def readiness_probe() -> Dict[str, Any]:
    """Kubernetes readiness probe endpoint."""
    try:
        # Check if critical services are ready
        ready = True
        services = {}
        
        # Check agent manager
        try:
            agent_manager = await get_agent_manager()
            services["agent_manager"] = "ready"
        except Exception as e:
            services["agent_manager"] = f"not_ready: {str(e)}"
            ready = False
        
        return {
            "status": "ready" if ready else "not_ready",
            "timestamp": time.time(),
            "services": services,
        }
        
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(status_code=503, detail=f"Service not ready: {str(e)}")


@router.get("/metrics")
async def get_metrics() -> Dict[str, Any]:
    """Get application metrics."""
    try:
        # System metrics
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Agent manager metrics
        agent_metrics = {}
        try:
            agent_manager = await get_agent_manager()
            agent_metrics = agent_manager.get_stats()
        except Exception as e:
            logger.warning(f"Could not get agent metrics: {str(e)}")
        
        return {
            "timestamp": time.time(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": (disk.used / disk.total) * 100,
                "memory_used_bytes": memory.used,
                "memory_total_bytes": memory.total,
                "disk_used_bytes": disk.used,
                "disk_total_bytes": disk.total,
            },
            "application": {
                "version": config.api.version,
                "environment": config.environment,
                "agents": agent_metrics,
            },
        }
        
    except Exception as e:
        logger.error(f"Metrics collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Metrics collection failed: {str(e)}")


@router.get("/version")
async def get_version() -> Dict[str, str]:
    """Get application version information."""
    return {
        "version": config.api.version,
        "name": config.app_name,
        "environment": config.environment,
        "timestamp": str(time.time()),
    } 