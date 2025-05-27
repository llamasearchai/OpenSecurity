"""Logging configuration for SecureML."""

import sys
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from loguru import logger

from backend.core.config import get_config


def setup_logging() -> None:
    """Configure logging for the application."""
    config = get_config()
    
    # Remove default handlers
    logger.remove()
    
    # Add console handler
    logger.add(
        sys.stderr,
        level=config.logging.level,
        format="{time} | {level} | {message}",
        backtrace=True,
        diagnose=True,
    )
    
    # Add file handler if enabled
    if config.logging.log_to_file:
        log_path = Path(config.logging.log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        logger.add(
            str(log_path),
            level=config.logging.level,
            format="{time} | {level} | {message}",
            rotation="10 MB",
            compression="zip",
            backtrace=True,
            diagnose=True,
        )


def get_logger(name: Optional[str] = None):
    """Get a logger instance."""
    if name:
        return logger.bind(context=name)
    return logger


# Initialize logging
setup_logging() 