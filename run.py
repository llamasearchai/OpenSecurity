#!/usr/bin/env python3
"""
SecureML Application Startup Script

This script provides a convenient way to start the SecureML application
with proper configuration and environment setup.
"""

import os
import sys
import argparse
from pathlib import Path

# Add the project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def setup_environment():
    """Setup environment variables with defaults."""
    env_defaults = {
        # OpenAI Configuration
        "SECUREML_OPENAI_MODEL": "gpt-4-turbo-preview",
        "SECUREML_OPENAI_TEMPERATURE": "0.1",
        "SECUREML_OPENAI_MAX_TOKENS": "4096",
        "SECUREML_OPENAI_TIMEOUT": "60",
        
        # Application Configuration
        "SECUREML_APP_NAME": "SecureML",
        "SECUREML_ENVIRONMENT": "development",
        "SECUREML_DEBUG": "true",
        
        # API Configuration
        "SECUREML_API_HOST": "0.0.0.0",
        "SECUREML_API_PORT": "8000",
        "SECUREML_API_DEBUG": "true",
        "SECUREML_API_TITLE": "SecureML API",
        "SECUREML_API_VERSION": "1.0.0",
        
        # Security Configuration
        "SECUREML_SECURITY_JWT_SECRET": "CHANGE_THIS_IN_PRODUCTION",
        "SECUREML_SECURITY_JWT_ALGORITHM": "HS256",
        "SECUREML_SECURITY_JWT_EXPIRES_MINUTES": "30",
        
        # Agent Configuration
        "SECUREML_AGENTS_ENABLED": "true",
        "SECUREML_AGENTS_MAX_CONCURRENT_AGENTS": "10",
        "SECUREML_AGENTS_AGENT_TIMEOUT": "300",
        
        # ML Configuration
        "SECUREML_ML_MODEL_PATH": "./models",
        "SECUREML_ML_CACHE_DIR": "./cache",
        "SECUREML_ML_EMBEDDING_MODEL": "all-MiniLM-L6-v2",
        "SECUREML_ML_DEVICE": "cpu",
        
        # Database Configuration
        "SECUREML_DATABASE_URL": "sqlite:///./secureml.db",
        "SECUREML_DATABASE_POOL_SIZE": "5",
        "SECUREML_DATABASE_MAX_OVERFLOW": "10",
        "SECUREML_DATABASE_ECHO": "false",
        
        # Logging Configuration
        "SECUREML_LOGGING_LEVEL": "INFO",
        "SECUREML_LOGGING_LOG_TO_FILE": "false",
        "SECUREML_LOGGING_LOG_FILE": "secureml.log",
    }
    
    # Set defaults only if not already set
    for key, value in env_defaults.items():
        if key not in os.environ:
            os.environ[key] = value


def check_requirements():
    """Check if required environment variables are set."""
    required_vars = [
        "SECUREML_OPENAI_API_KEY",
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        print("Missing required environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        print("\nPlease set these variables before starting the application.")
        print("You can set them in a .env file or as environment variables.")
        print("\nExample:")
        print(f"export SECUREML_OPENAI_API_KEY=your_api_key_here")
        return False
    
    return True


def create_directories():
    """Create necessary directories."""
    directories = [
        "models",
        "cache",
        "logs",
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="SecureML Application")
    parser.add_argument(
        "--host",
        default=None,
        help="Host to bind to (overrides environment variable)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (overrides environment variable)"
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable auto-reload for development"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of worker processes"
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default=None,
        help="Log level (overrides environment variable)"
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Check configuration and exit"
    )
    
    args = parser.parse_args()
    
    # Setup environment
    setup_environment()
    
    # Override with command line arguments
    if args.host:
        os.environ["SECUREML_API_HOST"] = args.host
    if args.port:
        os.environ["SECUREML_API_PORT"] = str(args.port)
    if args.log_level:
        os.environ["SECUREML_LOGGING_LEVEL"] = args.log_level.upper()
    
    # Check requirements
    if not check_requirements():
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Check configuration and exit if requested
    if args.check_config:
        print("Configuration check passed!")
        print(f"   - OpenAI API Key: {'Set' if os.environ.get('SECUREML_OPENAI_API_KEY') else 'Not set'}")
        print(f"   - Host: {os.environ.get('SECUREML_API_HOST')}")
        print(f"   - Port: {os.environ.get('SECUREML_API_PORT')}")
        print(f"   - Environment: {os.environ.get('SECUREML_ENVIRONMENT')}")
        print(f"   - Log Level: {os.environ.get('SECUREML_LOGGING_LEVEL')}")
        return
    
    # Import and start the application
    try:
        import uvicorn
        from backend.api.main import app
        
        print("Starting SecureML Application...")
        print(f"   - Environment: {os.environ.get('SECUREML_ENVIRONMENT')}")
        print(f"   - Host: {os.environ.get('SECUREML_API_HOST')}")
        print(f"   - Port: {os.environ.get('SECUREML_API_PORT')}")
        print(f"   - Workers: {args.workers}")
        print(f"   - Reload: {args.reload}")
        print()
        print("API Documentation: http://localhost:8000/docs")
        print("Health Check: http://localhost:8000/health/")
        print()
        
        uvicorn.run(
            "backend.api.main:app",
            host=os.environ.get("SECUREML_API_HOST", "0.0.0.0"),
            port=int(os.environ.get("SECUREML_API_PORT", "8000")),
            reload=args.reload,
            workers=args.workers if not args.reload else 1,
            log_level=os.environ.get("SECUREML_LOGGING_LEVEL", "info").lower(),
        )
        
    except ImportError as e:
        print(f"Import error: {e}")
        print("Please ensure all dependencies are installed:")
        print("   poetry install")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nShutting down SecureML Application...")
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main() 