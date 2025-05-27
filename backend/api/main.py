"""Main FastAPI application for SecureML with comprehensive endpoints."""

import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi

from backend.core.config import get_config
from backend.core.logging import get_logger
from backend.agents.manager import get_agent_manager
from backend.api.routes import agents, detectors, auth, health


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    logger = get_logger("api.main")
    logger.info("Starting SecureML API")
    
    # Initialize agent manager
    agent_manager = await get_agent_manager()
    logger.info("Agent manager initialized")
    
    yield
    
    # Cleanup
    await agent_manager.stop()
    logger.info("SecureML API shutdown complete")


# Initialize FastAPI app
config = get_config()
logger = get_logger("api")

app = FastAPI(
    title=config.api.title,
    description="ML-Driven Security Detection Platform with OpenAI Agents",
    version=config.api.version,
    docs_url=None,  # We'll create custom docs
    redoc_url=None,
    openapi_url=config.api.openapi_url,
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.security.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request timing middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next):
    """Add processing time to response headers."""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)
    return response


# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(agents.router, prefix="/agents", tags=["AI Agents"])
app.include_router(detectors.router, prefix="/detectors", tags=["Security Detectors"])
app.include_router(health.router, prefix="/health", tags=["Health"])


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema
    
    openapi_schema = get_openapi(
        title=config.api.title,
        version=config.api.version,
        description="""
# SecureML API

A comprehensive ML-driven security detection platform with OpenAI agents integration.

## Features

- **AI Agents**: Deploy and manage OpenAI-powered security analysis agents
- **Security Detectors**: ML-based threat detection and anomaly analysis
- **Real-time Processing**: Process security telemetry in real-time
- **Comprehensive Analytics**: Advanced security analytics and reporting

## Authentication

Most endpoints require authentication. Use the `/auth/login` endpoint to obtain a JWT token.

## Rate Limiting

API requests are rate-limited to prevent abuse. See response headers for current limits.
        """,
        routes=app.routes,
    )
    
    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
        }
    }
    
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# Custom docs endpoint
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Custom Swagger UI."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{config.api.title} - Documentation",
        swagger_js_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css",
    )


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """API root endpoint."""
    return {
        "name": config.app_name,
        "version": config.api.version,
        "status": "operational",
        "environment": config.environment,
        "timestamp": time.time(),
        "docs_url": "/docs",
        "openapi_url": config.api.openapi_url,
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle all uncaught exceptions."""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "type": "internal_error",
            "timestamp": time.time(),
        }
    )


# HTTP exception handler
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "type": "http_error",
            "status_code": exc.status_code,
            "timestamp": time.time(),
        }
    )


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "backend.api.main:app",
        host=config.api.host,
        port=config.api.port,
        reload=config.api.debug,
        log_level=config.logging.level.lower(),
    ) 