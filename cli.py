#!/usr/bin/env python3
"""
SecureML Command Line Interface

A comprehensive CLI tool for managing the SecureML security detection platform.
"""

import asyncio
import json
import sys
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
import click
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
import httpx

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from backend.core.config import get_config
from backend.core.logging import get_logger
from backend.detectors.manager import get_detector_manager, shutdown_detector_manager
from backend.agents.manager import get_agent_manager

console = Console()
logger = get_logger("cli")


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """SecureML - ML-Driven Security Detection Platform CLI"""
    pass


@cli.group()
def server():
    """Server management commands."""
    pass


@server.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
@click.option("--workers", default=1, help="Number of worker processes")
def start(host: str, port: int, reload: bool, workers: int):
    """Start the SecureML API server."""
    console.print(Panel.fit("🚀 Starting SecureML API Server", style="bold green"))
    
    config = get_config()
    
    # Override config with CLI options
    if host != "0.0.0.0":
        config.api.host = host
    if port != 8000:
        config.api.port = port
    
    console.print(f"Server starting on {config.api.host}:{config.api.port}")
    console.print(f"Environment: {config.environment}")
    console.print(f"Debug mode: {config.api.debug}")
    
    try:
        uvicorn.run(
            "backend.api.main:app",
            host=config.api.host,
            port=config.api.port,
            reload=reload or config.api.debug,
            workers=workers if not reload else 1,
            log_level=config.logging.level.lower(),
            access_log=True
        )
    except KeyboardInterrupt:
        console.print("\n👋 Server stopped by user")
    except Exception as e:
        console.print(f"❌ Error starting server: {e}", style="bold red")
        sys.exit(1)


@server.command()
@click.option("--config-file", help="Path to configuration file")
def validate(config_file: Optional[str]):
    """Validate server configuration."""
    console.print(Panel.fit("🔍 Validating Configuration", style="bold blue"))
    
    try:
        if config_file:
            # Load custom config file
            console.print(f"Loading config from: {config_file}")
        
        config = get_config()
        
        # Validate configuration
        errors = []
        warnings = []
        
        # Check OpenAI configuration
        if not config.openai.api_key:
            errors.append("OpenAI API key is not set")
        
        # Check security configuration
        if config.security.jwt_secret == "CHANGE_THIS_IN_PRODUCTION":
            if config.environment == "production":
                errors.append("JWT secret must be changed in production")
            else:
                warnings.append("JWT secret should be changed from default")
        
        # Check database configuration
        if "sqlite" in config.database.url and config.environment == "production":
            warnings.append("SQLite is not recommended for production")
        
        # Display results
        if errors:
            console.print("❌ Configuration Errors:", style="bold red")
            for error in errors:
                console.print(f"  • {error}", style="red")
        
        if warnings:
            console.print("⚠️  Configuration Warnings:", style="bold yellow")
            for warning in warnings:
                console.print(f"  • {warning}", style="yellow")
        
        if not errors and not warnings:
            console.print("✅ Configuration is valid!", style="bold green")
        
        # Display configuration summary
        table = Table(title="Configuration Summary")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Environment", config.environment)
        table.add_row("API Host", config.api.host)
        table.add_row("API Port", str(config.api.port))
        table.add_row("Debug Mode", str(config.api.debug))
        table.add_row("Database URL", config.database.url)
        table.add_row("OpenAI Model", config.openai.model)
        table.add_row("Agents Enabled", str(config.agents.enabled))
        table.add_row("Max Concurrent Agents", str(config.agents.max_concurrent_agents))
        
        console.print(table)
        
        if errors:
            sys.exit(1)
            
    except Exception as e:
        console.print(f"❌ Error validating configuration: {e}", style="bold red")
        sys.exit(1)


@cli.group()
def detectors():
    """Detector management commands."""
    pass


@detectors.command()
def list():
    """List all available detectors."""
    console.print(Panel.fit("🔍 Security Detectors", style="bold blue"))
    
    async def _list_detectors():
        try:
            detector_manager = await get_detector_manager()
            detectors_info = detector_manager.list_detectors()
            
            table = Table(title="Available Detectors")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="magenta")
            table.add_column("Type", style="green")
            table.add_column("Status", style="yellow")
            table.add_column("Processed", style="blue")
            table.add_column("Detected", style="red")
            
            for info in detectors_info:
                status = "✅ Enabled" if info["enabled"] else "❌ Disabled"
                stats = info["stats"]
                
                table.add_row(
                    info["id"],
                    info["name"],
                    info["description"].split()[0],  # First word as type
                    status,
                    str(stats.get("processed", 0)),
                    str(stats.get("detected", 0))
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"❌ Error listing detectors: {e}", style="bold red")
        finally:
            await shutdown_detector_manager()
    
    asyncio.run(_list_detectors())


@detectors.command()
@click.argument("detector_id")
def info(detector_id: str):
    """Get detailed information about a detector."""
    console.print(Panel.fit(f"🔍 Detector Info: {detector_id}", style="bold blue"))
    
    async def _detector_info():
        try:
            detector_manager = await get_detector_manager()
            detector = detector_manager.get_detector(detector_id)
            
            if not detector:
                console.print(f"❌ Detector '{detector_id}' not found", style="bold red")
                return
            
            # Basic info
            console.print(f"[bold]Name:[/bold] {detector.name}")
            console.print(f"[bold]Description:[/bold] {detector.description}")
            console.print(f"[bold]Type:[/bold] {detector.__class__.__name__}")
            console.print(f"[bold]Status:[/bold] {'✅ Enabled' if detector.enabled else '❌ Disabled'}")
            
            # Statistics
            stats = detector.get_stats()
            stats_table = Table(title="Statistics")
            stats_table.add_column("Metric", style="cyan")
            stats_table.add_column("Value", style="magenta")
            
            for key, value in stats.items():
                stats_table.add_row(key.replace("_", " ").title(), str(value))
            
            console.print(stats_table)
            
            # Configuration
            config = detector.get_configuration()
            if config:
                config_table = Table(title="Configuration")
                config_table.add_column("Setting", style="cyan")
                config_table.add_column("Value", style="magenta")
                
                for key, value in config.items():
                    config_table.add_row(key, str(value))
                
                console.print(config_table)
            
        except Exception as e:
            console.print(f"❌ Error getting detector info: {e}", style="bold red")
        finally:
            await shutdown_detector_manager()
    
    asyncio.run(_detector_info())


@detectors.command()
@click.argument("detector_id")
def enable(detector_id: str):
    """Enable a detector."""
    async def _enable_detector():
        try:
            detector_manager = await get_detector_manager()
            detector_manager.enable_detector(detector_id)
            console.print(f"✅ Detector '{detector_id}' enabled", style="bold green")
        except ValueError as e:
            console.print(f"❌ {e}", style="bold red")
        except Exception as e:
            console.print(f"❌ Error enabling detector: {e}", style="bold red")
        finally:
            await shutdown_detector_manager()
    
    asyncio.run(_enable_detector())


@detectors.command()
@click.argument("detector_id")
def disable(detector_id: str):
    """Disable a detector."""
    async def _disable_detector():
        try:
            detector_manager = await get_detector_manager()
            detector_manager.disable_detector(detector_id)
            console.print(f"❌ Detector '{detector_id}' disabled", style="bold yellow")
        except ValueError as e:
            console.print(f"❌ {e}", style="bold red")
        except Exception as e:
            console.print(f"❌ Error disabling detector: {e}", style="bold red")
        finally:
            await shutdown_detector_manager()
    
    asyncio.run(_disable_detector())


@detectors.command()
@click.argument("data_file", type=click.Path(exists=True))
@click.option("--detector-id", help="Specific detector to use")
@click.option("--output", help="Output file for results")
def detect(data_file: str, detector_id: Optional[str], output: Optional[str]):
    """Run detection on data from a file."""
    console.print(Panel.fit("🔍 Running Detection", style="bold blue"))
    
    async def _run_detection():
        try:
            # Load data
            with open(data_file, 'r') as f:
                if data_file.endswith('.json'):
                    data = json.load(f)
                else:
                    # Assume each line is a JSON object
                    data = [json.loads(line) for line in f if line.strip()]
            
            console.print(f"Loaded {len(data) if isinstance(data, list) else 1} data items")
            
            # Run detection
            detector_manager = await get_detector_manager()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Running detection...", total=None)
                
                detector_ids = [detector_id] if detector_id else None
                results = await detector_manager.detect(data, detector_ids)
                
                progress.update(task, description="Detection complete!")
            
            # Display results
            if results:
                console.print(f"🚨 Found {len(results)} detections", style="bold red")
                
                results_table = Table(title="Detection Results")
                results_table.add_column("Detector", style="cyan")
                results_table.add_column("Severity", style="red")
                results_table.add_column("Confidence", style="yellow")
                results_table.add_column("Description", style="white")
                
                for result in results[:10]:  # Show first 10 results
                    results_table.add_row(
                        result.detector_name,
                        result.severity.value.upper(),
                        f"{result.confidence:.2f}",
                        result.description[:50] + "..." if len(result.description) > 50 else result.description
                    )
                
                console.print(results_table)
                
                if len(results) > 10:
                    console.print(f"... and {len(results) - 10} more results")
                
                # Save results if requested
                if output:
                    results_data = [result.to_dict() for result in results]
                    with open(output, 'w') as f:
                        json.dump(results_data, f, indent=2, default=str)
                    console.print(f"💾 Results saved to {output}")
            else:
                console.print("✅ No threats detected", style="bold green")
            
        except Exception as e:
            console.print(f"❌ Error running detection: {e}", style="bold red")
        finally:
            await shutdown_detector_manager()
    
    asyncio.run(_run_detection())


@detectors.command()
def health():
    """Check detector health status."""
    console.print(Panel.fit("🏥 Detector Health Check", style="bold blue"))
    
    async def _health_check():
        try:
            detector_manager = await get_detector_manager()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Checking detector health...", total=None)
                health_status = await detector_manager.health_check()
                progress.update(task, description="Health check complete!")
            
            # Overall status
            overall_status = "✅ Healthy" if health_status["overall_healthy"] else "❌ Unhealthy"
            console.print(f"[bold]Overall Status:[/bold] {overall_status}")
            console.print(f"[bold]Manager Status:[/bold] {'✅ Healthy' if health_status['manager_healthy'] else '❌ Unhealthy'}")
            
            # Individual detector status
            table = Table(title="Detector Health Status")
            table.add_column("Detector ID", style="cyan")
            table.add_column("Status", style="green")
            table.add_column("Enabled", style="yellow")
            table.add_column("Error", style="red")
            
            for detector_id, health_info in health_status["detectors_healthy"].items():
                status = "✅ Healthy" if health_info["healthy"] else "❌ Unhealthy"
                enabled = "✅ Yes" if health_info["enabled"] else "❌ No"
                error = health_info.get("error", "None")
                
                table.add_row(detector_id, status, enabled, error)
            
            console.print(table)
            
        except Exception as e:
            console.print(f"❌ Error checking health: {e}", style="bold red")
        finally:
            await shutdown_detector_manager()
    
    asyncio.run(_health_check())


@cli.group()
def agents():
    """AI agent management commands."""
    pass


@agents.command()
def list():
    """List all AI agents."""
    console.print(Panel.fit("🤖 AI Agents", style="bold blue"))
    
    async def _list_agents():
        try:
            agent_manager = await get_agent_manager()
            agents_info = agent_manager.list_agents()
            
            if not agents_info:
                console.print("No agents found", style="yellow")
                return
            
            table = Table(title="Active Agents")
            table.add_column("Agent ID", style="cyan")
            table.add_column("Type", style="magenta")
            table.add_column("Status", style="green")
            table.add_column("Tasks", style="yellow")
            table.add_column("Created", style="blue")
            
            for agent_info in agents_info:
                table.add_row(
                    agent_info.get("agent_id", "Unknown"),
                    agent_info.get("agent_type", "Unknown"),
                    agent_info.get("status", "Unknown"),
                    str(agent_info.get("task_count", 0)),
                    agent_info.get("created_at", "Unknown")
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"❌ Error listing agents: {e}", style="bold red")
    
    asyncio.run(_list_agents())


@agents.command()
@click.argument("agent_type")
@click.option("--agent-id", help="Custom agent ID")
def create(agent_type: str, agent_id: Optional[str]):
    """Create a new AI agent."""
    console.print(Panel.fit(f"🤖 Creating Agent: {agent_type}", style="bold blue"))
    
    async def _create_agent():
        try:
            agent_manager = await get_agent_manager()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("Creating agent...", total=None)
                
                agent = await agent_manager.create_agent(
                    agent_type=agent_type,
                    agent_id=agent_id
                )
                
                progress.update(task, description="Agent created!")
            
            console.print(f"✅ Agent created successfully", style="bold green")
            console.print(f"Agent ID: {agent.agent_id}")
            console.print(f"Agent Type: {agent.agent_type}")
            
        except Exception as e:
            console.print(f"❌ Error creating agent: {e}", style="bold red")
    
    asyncio.run(_create_agent())


@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command()
def show():
    """Show current configuration."""
    console.print(Panel.fit("⚙️  Current Configuration", style="bold blue"))
    
    try:
        config = get_config()
        
        # Create configuration display
        sections = [
            ("Application", {
                "Name": config.app_name,
                "Environment": config.environment,
                "Debug": config.debug
            }),
            ("API", {
                "Host": config.api.host,
                "Port": config.api.port,
                "Debug": config.api.debug,
                "Title": config.api.title,
                "Version": config.api.version
            }),
            ("OpenAI", {
                "Model": config.openai.model,
                "Temperature": config.openai.temperature,
                "Max Tokens": config.openai.max_tokens,
                "Timeout": config.openai.timeout,
                "API Key Set": "Yes" if config.openai.api_key else "No"
            }),
            ("Security", {
                "JWT Algorithm": config.security.jwt_algorithm,
                "JWT Expires (min)": config.security.jwt_expires_minutes,
                "Allowed Origins": len(config.security.allowed_origins)
            }),
            ("Agents", {
                "Enabled": config.agents.enabled,
                "Max Concurrent": config.agents.max_concurrent_agents,
                "Timeout": config.agents.agent_timeout,
                "Memory Backend": config.agents.memory_backend
            }),
            ("Machine Learning", {
                "Model Path": config.ml.model_path,
                "Cache Dir": config.ml.cache_dir,
                "Embedding Model": config.ml.embedding_model,
                "Device": config.ml.device
            }),
            ("Database", {
                "URL": config.database.url,
                "Pool Size": config.database.pool_size,
                "Max Overflow": config.database.max_overflow,
                "Echo": config.database.echo
            }),
            ("Logging", {
                "Level": config.logging.level,
                "Log to File": config.logging.log_to_file,
                "Log File": config.logging.log_file
            })
        ]
        
        for section_name, section_config in sections:
            table = Table(title=section_name)
            table.add_column("Setting", style="cyan")
            table.add_column("Value", style="magenta")
            
            for key, value in section_config.items():
                table.add_row(key, str(value))
            
            console.print(table)
            console.print()
        
    except Exception as e:
        console.print(f"❌ Error showing configuration: {e}", style="bold red")


@config.command()
@click.option("--output", default=".env.example", help="Output file")
def generate(output: str):
    """Generate environment configuration template."""
    console.print(Panel.fit("📝 Generating Configuration Template", style="bold blue"))
    
    try:
        template = """# SecureML Environment Configuration
# Copy this file to .env and update the values

# =============================================================================
# CORE APPLICATION SETTINGS
# =============================================================================
SECUREML_APP_NAME=SecureML
SECUREML_ENVIRONMENT=development
SECUREML_DEBUG=true

# =============================================================================
# API CONFIGURATION
# =============================================================================
SECUREML_API_HOST=0.0.0.0
SECUREML_API_PORT=8000
SECUREML_API_DEBUG=true

# =============================================================================
# OPENAI CONFIGURATION
# =============================================================================
# REQUIRED: Get your API key from https://platform.openai.com/api-keys
SECUREML_OPENAI_API_KEY=your_openai_api_key_here

# OPTIONAL: OpenAI organization ID
SECUREML_OPENAI_ORGANIZATION=your_org_id_here

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
# REQUIRED: Change this to a secure random string in production
SECUREML_SECURITY_JWT_SECRET=your_super_secret_jwt_key_here_change_in_production

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================
SECUREML_LOGGING_LEVEL=INFO
SECUREML_LOGGING_LOG_TO_FILE=false
SECUREML_LOGGING_LOG_FILE=secureml.log
"""
        
        with open(output, 'w') as f:
            f.write(template)
        
        console.print(f"✅ Configuration template generated: {output}", style="bold green")
        console.print("📝 Edit the file and copy to .env to use")
        
    except Exception as e:
        console.print(f"❌ Error generating configuration: {e}", style="bold red")


@cli.group()
def status():
    """System status commands."""
    pass


@status.command()
@click.option("--api-url", default="http://localhost:8000", help="API base URL")
def check(api_url: str):
    """Check system status via API."""
    console.print(Panel.fit("📊 System Status Check", style="bold blue"))
    
    async def _check_status():
        try:
            async with httpx.AsyncClient() as client:
                # Check API health
                try:
                    response = await client.get(f"{api_url}/health/")
                    if response.status_code == 200:
                        console.print("✅ API is healthy", style="bold green")
                        health_data = response.json()
                        
                        # Display health information
                        table = Table(title="Health Status")
                        table.add_column("Component", style="cyan")
                        table.add_column("Status", style="green")
                        
                        for key, value in health_data.items():
                            if isinstance(value, bool):
                                status = "✅ OK" if value else "❌ Error"
                            else:
                                status = str(value)
                            table.add_row(key.replace("_", " ").title(), status)
                        
                        console.print(table)
                    else:
                        console.print(f"❌ API health check failed: {response.status_code}", style="bold red")
                except httpx.ConnectError:
                    console.print("❌ Cannot connect to API server", style="bold red")
                    console.print(f"Make sure the server is running on {api_url}")
                
                # Check root endpoint
                try:
                    response = await client.get(f"{api_url}/")
                    if response.status_code == 200:
                        root_data = response.json()
                        console.print(f"📡 API Version: {root_data.get('version', 'Unknown')}")
                        console.print(f"🌍 Environment: {root_data.get('environment', 'Unknown')}")
                except:
                    pass
        
        except Exception as e:
            console.print(f"❌ Error checking status: {e}", style="bold red")
    
    asyncio.run(_check_status())


@cli.command()
def init():
    """Initialize SecureML project."""
    console.print(Panel.fit("🚀 Initializing SecureML Project", style="bold green"))
    
    # Create necessary directories
    directories = [
        "models",
        "cache", 
        "logs",
        "data"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        console.print(f"📁 Created directory: {directory}")
    
    # Generate configuration if it doesn't exist
    if not Path(".env").exists():
        if not Path(".env.example").exists():
            # Generate .env.example
            ctx = click.Context(config.generate)
            ctx.invoke(config.generate)
        
        if Confirm.ask("Generate .env file from template?"):
            import shutil
            shutil.copy(".env.example", ".env")
            console.print("📝 Created .env file from template")
            console.print("⚠️  Please edit .env file with your configuration")
    
    console.print("✅ SecureML project initialized!", style="bold green")
    console.print("\n📋 Next steps:")
    console.print("1. Edit .env file with your configuration")
    console.print("2. Set your OpenAI API key")
    console.print("3. Run 'python cli.py server start' to start the server")


if __name__ == "__main__":
    cli() 