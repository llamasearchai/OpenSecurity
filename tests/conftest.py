"""Test configuration and fixtures for SecureML."""

import asyncio
import pytest
import pytest_asyncio
from typing import Dict, Any, AsyncGenerator
from unittest.mock import Mock, AsyncMock

from fastapi.testclient import TestClient
from httpx import AsyncClient

from backend.core.config import Config
from backend.api.main import app
from backend.agents.manager import AgentManager
from backend.agents.base import SecurityAnalystAgent, AgentTask


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config():
    """Test configuration."""
    return Config(
        environment="testing",
        debug=True,
        openai=Config.OpenAIConfig(
            api_key="test-key",
            model="gpt-3.5-turbo",
            temperature=0.1,
        ),
        agents=Config.AgentsConfig(
            enabled=True,
            max_concurrent_agents=5,
        ),
        security=Config.SecurityConfig(
            jwt_secret="test-secret-key",
            jwt_expires_minutes=30,
        ),
        logging=Config.LoggingConfig(
            level="DEBUG",
            log_to_file=False,
        ),
    )


@pytest.fixture
def client():
    """Test client for FastAPI app."""
    return TestClient(app)


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async test client for FastAPI app."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    mock_client = AsyncMock()
    
    # Mock chat completion response
    mock_response = Mock()
    mock_response.choices = [Mock()]
    mock_response.choices[0].message.content = "Test response from AI agent"
    mock_response.usage.total_tokens = 100
    
    mock_client.chat.completions.create.return_value = mock_response
    
    return mock_client


@pytest_asyncio.fixture
async def agent_manager():
    """Test agent manager."""
    manager = AgentManager(max_concurrent_agents=3)
    await manager.start()
    yield manager
    await manager.stop()


@pytest_asyncio.fixture
async def security_agent(mock_openai_client):
    """Test security analyst agent."""
    agent = SecurityAnalystAgent("test-security-agent")
    agent.openai_client = mock_openai_client
    return agent


@pytest.fixture
def sample_log_data():
    """Sample log data for testing."""
    return {
        "logs": [
            {
                "timestamp": "2024-01-01T10:00:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "port": 22,
                "protocol": "SSH",
                "action": "ACCEPT",
                "bytes": 1024,
            },
            {
                "timestamp": "2024-01-01T10:01:00Z",
                "source_ip": "192.168.1.100",
                "destination_ip": "10.0.0.1",
                "port": 22,
                "protocol": "SSH",
                "action": "ACCEPT",
                "bytes": 2048,
            },
        ],
        "log_type": "firewall",
    }


@pytest.fixture
def sample_threat_data():
    """Sample threat data for testing."""
    return {
        "threat_data": {
            "indicator": "malicious-domain.com",
            "type": "domain",
            "confidence": 0.9,
            "first_seen": "2024-01-01T09:00:00Z",
            "last_seen": "2024-01-01T10:00:00Z",
            "tags": ["malware", "c2"],
        },
        "context": {
            "network": "corporate",
            "criticality": "high",
            "affected_systems": ["web-server-01", "db-server-02"],
        },
    }


@pytest.fixture
def sample_incident_data():
    """Sample incident data for testing."""
    return {
        "incident_data": {
            "id": "INC-2024-001",
            "title": "Suspicious Network Activity",
            "description": "Multiple failed login attempts detected",
            "severity": "high",
            "affected_systems": ["web-server-01"],
            "indicators": [
                {
                    "type": "ip",
                    "value": "192.168.1.100",
                    "confidence": 0.8,
                }
            ],
            "timeline": [
                {
                    "timestamp": "2024-01-01T10:00:00Z",
                    "event": "First failed login attempt",
                },
                {
                    "timestamp": "2024-01-01T10:05:00Z",
                    "event": "Multiple failed attempts detected",
                },
            ],
        }
    }


@pytest.fixture
def auth_headers():
    """Authentication headers for testing."""
    # In a real test, you'd generate a proper JWT token
    return {"Authorization": "Bearer test-token"}


@pytest.fixture
def sample_agent_task():
    """Sample agent task for testing."""
    return AgentTask(
        name="Test Security Analysis",
        description="Analyze sample security data",
        input_data={
            "type": "log_analysis",
            "logs": [
                {
                    "timestamp": "2024-01-01T10:00:00Z",
                    "event": "Failed login attempt",
                    "source_ip": "192.168.1.100",
                    "user": "admin",
                }
            ],
            "log_type": "authentication",
        },
        priority=5,
        timeout=300,
    )


@pytest.fixture
def mock_detector():
    """Mock security detector for testing."""
    from backend.detectors.base import BaseDetector, DetectionResult, DetectionSeverity
    
    class MockDetector(BaseDetector):
        def __init__(self):
            super().__init__(
                id="mock-detector",
                name="Mock Security Detector",
                description="A mock detector for testing",
            )
        
        async def process(self, data):
            # Return mock detection results
            return [
                DetectionResult(
                    detector_id=self.id,
                    detector_name=self.name,
                    severity=DetectionSeverity.MEDIUM,
                    confidence=0.8,
                    description="Mock threat detected",
                    raw_data=data,
                    entities=["192.168.1.100"],
                    tactics=["Initial Access"],
                    techniques=["T1078"],
                )
            ]
        
        async def train(self, training_data):
            pass
        
        def get_configuration(self):
            return {"threshold": 0.7, "enabled": True}
        
        def set_configuration(self, config):
            pass
    
    return MockDetector()


# Pytest markers for test categorization
pytest_plugins = ["pytest_asyncio"]

# Test data generators
class TestDataGenerator:
    """Generate test data for various scenarios."""
    
    @staticmethod
    def generate_network_logs(count: int = 10) -> list:
        """Generate sample network logs."""
        import random
        from datetime import datetime, timedelta
        
        logs = []
        base_time = datetime.utcnow()
        
        for i in range(count):
            logs.append({
                "timestamp": (base_time + timedelta(minutes=i)).isoformat(),
                "source_ip": f"192.168.1.{random.randint(1, 254)}",
                "destination_ip": f"10.0.0.{random.randint(1, 254)}",
                "port": random.choice([22, 80, 443, 3389, 21]),
                "protocol": random.choice(["TCP", "UDP"]),
                "action": random.choice(["ACCEPT", "DENY"]),
                "bytes": random.randint(64, 65536),
            })
        
        return logs
    
    @staticmethod
    def generate_security_events(count: int = 5) -> list:
        """Generate sample security events."""
        import random
        from datetime import datetime, timedelta
        
        events = []
        base_time = datetime.utcnow()
        
        event_types = [
            "Failed Login",
            "Malware Detection",
            "Suspicious Network Activity",
            "Privilege Escalation",
            "Data Exfiltration",
        ]
        
        for i in range(count):
            events.append({
                "timestamp": (base_time + timedelta(minutes=i * 5)).isoformat(),
                "event_type": random.choice(event_types),
                "severity": random.choice(["low", "medium", "high", "critical"]),
                "source": f"system-{random.randint(1, 10)}",
                "description": f"Security event {i + 1}",
                "indicators": [
                    {
                        "type": "ip",
                        "value": f"192.168.1.{random.randint(1, 254)}",
                    }
                ],
            })
        
        return events


@pytest.fixture
def test_data_generator():
    """Test data generator fixture."""
    return TestDataGenerator() 