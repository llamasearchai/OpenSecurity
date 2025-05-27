"""Configuration management for SecureML with OpenAI integration."""

import os
from typing import List, Optional, Dict, Any, Union
from pathlib import Path

from pydantic import BaseSettings, Field, validator
from pydantic_settings import SettingsConfigDict


class DatabaseConfig(BaseSettings):
    """Database configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_DATABASE_")
    
    url: str = Field(default="sqlite:///./secureml.db", description="Database URL")
    pool_size: int = Field(default=5, description="Connection pool size")
    max_overflow: int = Field(default=10, description="Max overflow connections")
    echo: bool = Field(default=False, description="Echo SQL queries")


class OpenAIConfig(BaseSettings):
    """OpenAI configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_OPENAI_")
    
    api_key: Optional[str] = Field(default=None, description="OpenAI API key")
    organization: Optional[str] = Field(default=None, description="OpenAI organization")
    model: str = Field(default="gpt-4-turbo-preview", description="Default model")
    temperature: float = Field(default=0.1, description="Temperature for generation")
    max_tokens: int = Field(default=4096, description="Max tokens per request")
    timeout: int = Field(default=60, description="Request timeout in seconds")


class AgentsConfig(BaseSettings):
    """AI Agents configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_AGENTS_")
    
    enabled: bool = Field(default=True, description="Enable AI agents")
    max_concurrent_agents: int = Field(default=10, description="Max concurrent agents")
    agent_timeout: int = Field(default=300, description="Agent timeout in seconds")
    memory_backend: str = Field(default="redis", description="Memory backend for agents")


class MLConfig(BaseSettings):
    """Machine Learning configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_ML_")
    
    model_path: str = Field(default="./models", description="Path to store ML models")
    cache_dir: str = Field(default="./cache", description="Cache directory")
    embedding_model: str = Field(default="all-MiniLM-L6-v2", description="Embedding model")
    device: str = Field(default="cpu", description="Device for ML computations")


class SecurityConfig(BaseSettings):
    """Security configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_SECURITY_")
    
    jwt_secret: str = Field(default="CHANGE_THIS_IN_PRODUCTION", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_expires_minutes: int = Field(default=30, description="JWT expiration in minutes")
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:8000"],
        description="Allowed CORS origins"
    )


class LoggingConfig(BaseSettings):
    """Logging configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_LOGGING_")
    
    level: str = Field(default="INFO", description="Logging level")
    log_to_file: bool = Field(default=False, description="Log to file")
    log_file: str = Field(default="secureml.log", description="Log file path")


class APIConfig(BaseSettings):
    """API configuration."""
    
    model_config = SettingsConfigDict(env_prefix="SECUREML_API_")
    
    host: str = Field(default="0.0.0.0", description="API host")
    port: int = Field(default=8000, description="API port")
    debug: bool = Field(default=False, description="Enable debug mode")
    title: str = Field(default="SecureML API", description="API title")
    version: str = Field(default="1.0.0", description="API version")
    openapi_url: str = Field(default="/openapi.json", description="OpenAPI schema URL")


class Config(BaseSettings):
    """Main configuration class."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application settings
    app_name: str = Field(default="SecureML", description="Application name")
    environment: str = Field(default="development", description="Environment")
    debug: bool = Field(default=False, description="Debug mode")
    
    # Component configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    openai: OpenAIConfig = Field(default_factory=OpenAIConfig)
    agents: AgentsConfig = Field(default_factory=AgentsConfig)
    ml: MLConfig = Field(default_factory=MLConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    
    @validator("environment")
    def validate_environment(cls, v: str) -> str:
        """Validate environment setting."""
        allowed = ["development", "testing", "staging", "production"]
        if v not in allowed:
            raise ValueError(f"Environment must be one of: {allowed}")
        return v
    
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"


# Global configuration instance
config = Config()


def get_config() -> Config:
    """Get the global configuration instance."""
    return config 