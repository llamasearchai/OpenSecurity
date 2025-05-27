"""Tests for the FastAPI endpoints."""

import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from fastapi.testclient import TestClient

from backend.api.main import app
from backend.api.routes.auth import create_access_token


class TestRootEndpoints:
    """Test root API endpoints."""
    
    def test_root_endpoint(self, client):
        """Test the root endpoint."""
        response = client.get("/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "SecureML"
        assert data["status"] == "operational"
        assert "version" in data
        assert "timestamp" in data
    
    def test_docs_endpoint(self, client):
        """Test the documentation endpoint."""
        response = client.get("/docs")
        
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    def test_openapi_endpoint(self, client):
        """Test the OpenAPI schema endpoint."""
        response = client.get("/openapi.json")
        
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "info" in schema
        assert schema["info"]["title"] == "SecureML API"


class TestAuthEndpoints:
    """Test authentication endpoints."""
    
    def test_login_success(self, client):
        """Test successful login."""
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user_info" in data
        assert data["user_info"]["username"] == "admin"
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials."""
        response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "wrong_password"}
        )
        
        assert response.status_code == 401
        data = response.json()
        assert "detail" in data
    
    def test_login_nonexistent_user(self, client):
        """Test login with nonexistent user."""
        response = client.post(
            "/auth/login",
            json={"username": "nonexistent", "password": "password"}
        )
        
        assert response.status_code == 401
    
    def test_get_current_user(self, client):
        """Test getting current user info."""
        # First login to get token
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        
        # Use token to get user info
        response = client.get(
            "/auth/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "admin"
        assert data["email"] == "admin@secureml.com"
        assert "admin" in data["roles"]
    
    def test_get_current_user_invalid_token(self, client):
        """Test getting user info with invalid token."""
        response = client.get(
            "/auth/me",
            headers={"Authorization": "Bearer invalid_token"}
        )
        
        assert response.status_code == 401
    
    def test_logout(self, client):
        """Test logout."""
        # First login
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        
        # Logout
        response = client.post(
            "/auth/logout",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "message" in data
    
    def test_refresh_token(self, client):
        """Test token refresh."""
        # First login
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        
        # Refresh token
        response = client.post(
            "/auth/refresh",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
    
    def test_validate_token(self, client):
        """Test token validation."""
        # First login
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        
        # Validate token
        response = client.get(
            "/auth/validate",
            headers={"Authorization": f"Bearer {token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["valid"] is True
        assert data["user"]["username"] == "admin"


class TestAgentEndpoints:
    """Test agent management endpoints."""
    
    def get_auth_headers(self, client):
        """Helper to get authentication headers."""
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_list_agents(self, mock_get_manager, client):
        """Test listing agents."""
        # Mock agent manager
        mock_manager = AsyncMock()
        mock_manager.list_agents.return_value = [
            {
                "agent_id": "test-agent-1",
                "name": "Test Agent 1",
                "status": "idle",
                "capabilities": [],
                "stats": {"tasks_completed": 0},
                "created_at": "2024-01-01T00:00:00",
                "last_activity": "2024-01-01T00:00:00",
            }
        ]
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.get("/agents/", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["agent_id"] == "test-agent-1"
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_create_agent(self, mock_get_manager, client):
        """Test creating an agent."""
        # Mock agent manager and agent
        mock_agent = Mock()
        mock_agent.get_status.return_value = {
            "agent_id": "new-agent",
            "name": "New Agent",
            "status": "idle",
            "capabilities": [],
            "stats": {"tasks_completed": 0},
            "created_at": "2024-01-01T00:00:00",
            "last_activity": "2024-01-01T00:00:00",
        }
        
        mock_manager = AsyncMock()
        mock_manager.create_agent.return_value = mock_agent
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.post(
            "/agents/",
            headers=headers,
            json={
                "agent_type": "security_analyst",
                "agent_id": "new-agent"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "new-agent"
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_get_agent(self, mock_get_manager, client):
        """Test getting a specific agent."""
        # Mock agent
        mock_agent = Mock()
        mock_agent.get_status.return_value = {
            "agent_id": "test-agent",
            "name": "Test Agent",
            "status": "idle",
            "capabilities": [],
            "stats": {"tasks_completed": 0},
            "created_at": "2024-01-01T00:00:00",
            "last_activity": "2024-01-01T00:00:00",
        }
        
        mock_manager = AsyncMock()
        mock_manager.get_agent.return_value = mock_agent
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.get("/agents/test-agent", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "test-agent"
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_get_nonexistent_agent(self, mock_get_manager, client):
        """Test getting a nonexistent agent."""
        mock_manager = AsyncMock()
        mock_manager.get_agent.return_value = None
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.get("/agents/nonexistent", headers=headers)
        
        assert response.status_code == 404
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_delete_agent(self, mock_get_manager, client):
        """Test deleting an agent."""
        mock_manager = AsyncMock()
        mock_manager.remove_agent.return_value = True
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.delete("/agents/test-agent", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "deleted successfully" in data["message"]
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_create_task(self, mock_get_manager, client):
        """Test creating a task."""
        mock_manager = AsyncMock()
        mock_manager.submit_task.return_value = "task-123"
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.post(
            "/agents/tasks",
            headers=headers,
            json={
                "name": "Test Task",
                "description": "A test task",
                "input_data": {"test": "data"},
                "priority": 5,
                "agent_id": "test-agent"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "task-123"
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_get_task_status(self, mock_get_manager, client):
        """Test getting task status."""
        mock_manager = AsyncMock()
        mock_manager.get_task_status.return_value = {
            "id": "task-123",
            "name": "Test Task",
            "status": "completed",
            "result": {"test": "result"},
            "agent_id": "test-agent",
            "created_at": "2024-01-01T00:00:00",
        }
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.get("/agents/tasks/task-123", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "task-123"
        assert data["status"] == "completed"
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_cancel_task(self, mock_get_manager, client):
        """Test cancelling a task."""
        mock_manager = AsyncMock()
        mock_manager.cancel_task.return_value = True
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.delete("/agents/tasks/task-123", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert "cancelled successfully" in data["message"]
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_broadcast_message(self, mock_get_manager, client):
        """Test broadcasting a message."""
        mock_manager = AsyncMock()
        mock_manager.broadcast_message.return_value = {
            "agent-1": "Response from agent 1",
            "agent-2": "Response from agent 2"
        }
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.post(
            "/agents/broadcast",
            headers=headers,
            json={"message": "Test broadcast"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "agent-1" in data
        assert "agent-2" in data
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_get_manager_stats(self, mock_get_manager, client):
        """Test getting manager statistics."""
        mock_manager = AsyncMock()
        mock_manager.get_stats.return_value = {
            "total_agents": 2,
            "active_agents": 1,
            "queued_tasks": 0,
            "running_tasks": 1,
            "completed_tasks": 5
        }
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.get("/agents/stats/manager", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_agents"] == 2
        assert data["completed_tasks"] == 5
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_send_message_to_agent(self, mock_get_manager, client):
        """Test sending a message to a specific agent."""
        mock_agent = AsyncMock()
        mock_agent.get_response.return_value = "Agent response"
        
        mock_manager = AsyncMock()
        mock_manager.get_agent.return_value = mock_agent
        mock_get_manager.return_value = mock_manager
        
        headers = self.get_auth_headers(client)
        response = client.post(
            "/agents/test-agent/message",
            headers=headers,
            json="Hello agent"
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["response"] == "Agent response"
    
    def test_unauthorized_access(self, client):
        """Test unauthorized access to agent endpoints."""
        response = client.get("/agents/")
        assert response.status_code == 401


class TestDetectorEndpoints:
    """Test detector endpoints."""
    
    def get_auth_headers(self, client):
        """Helper to get authentication headers."""
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}
    
    @patch('backend.api.routes.detectors.DETECTORS')
    def test_list_detectors(self, mock_detectors, client):
        """Test listing detectors."""
        # Mock detector
        mock_detector = Mock()
        mock_detector.id = "test-detector"
        mock_detector.name = "Test Detector"
        mock_detector.description = "A test detector"
        mock_detector.__class__.__name__ = "TestDetector"
        mock_detector.enabled = True
        mock_detector.get_stats.return_value = {"processed": 10}
        
        mock_detectors.__iter__.return_value = iter([("test-detector", mock_detector)])
        mock_detectors.items.return_value = [("test-detector", mock_detector)]
        
        headers = self.get_auth_headers(client)
        response = client.get("/detectors/", headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 1
        assert data[0]["id"] == "test-detector"
    
    @patch('backend.api.routes.detectors.DETECTORS')
    def test_run_detection(self, mock_detectors, client):
        """Test running detection."""
        # Mock detector
        mock_detector = AsyncMock()
        mock_detector.id = "test-detector"
        mock_detector.name = "Test Detector"
        mock_detector.enabled = True
        mock_detector.process.return_value = [
            Mock(to_dict=lambda: {
                "id": "detection-1",
                "severity": "medium",
                "confidence": 0.8,
                "description": "Test detection"
            })
        ]
        
        mock_detectors.values.return_value = [mock_detector]
        
        headers = self.get_auth_headers(client)
        response = client.post(
            "/detectors/detect",
            headers=headers,
            json={"data": {"test": "data"}}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["detection_count"] == 1
        assert len(data["results"]) == 1


class TestHealthEndpoints:
    """Test health check endpoints."""
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.disk_usage')
    @patch('backend.agents.manager.get_agent_manager')
    def test_health_check(self, mock_get_manager, mock_disk, mock_memory, mock_cpu, client):
        """Test comprehensive health check."""
        # Mock system metrics
        mock_cpu.return_value = 50.0
        mock_memory.return_value = Mock(
            total=8000000000,
            available=4000000000,
            percent=50.0,
            used=4000000000,
            free=4000000000
        )
        mock_disk.return_value = Mock(
            total=100000000000,
            used=50000000000,
            free=50000000000
        )
        
        # Mock agent manager
        mock_manager = AsyncMock()
        mock_manager.health_check.return_value = {
            "manager_status": "healthy",
            "agents": {},
            "issues": []
        }
        mock_get_manager.return_value = mock_manager
        
        response = client.get("/health/")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded", "unhealthy"]
        assert "system" in data
        assert "services" in data
        assert "timestamp" in data
    
    def test_liveness_probe(self, client):
        """Test liveness probe."""
        response = client.get("/health/liveness")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "alive"
        assert "timestamp" in data
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_readiness_probe(self, mock_get_manager, client):
        """Test readiness probe."""
        mock_manager = AsyncMock()
        mock_get_manager.return_value = mock_manager
        
        response = client.get("/health/readiness")
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["ready", "not_ready"]
        assert "services" in data
    
    @patch('psutil.cpu_percent')
    @patch('psutil.virtual_memory')
    @patch('psutil.disk_usage')
    @patch('backend.agents.manager.get_agent_manager')
    def test_metrics(self, mock_get_manager, mock_disk, mock_memory, mock_cpu, client):
        """Test metrics endpoint."""
        # Mock system metrics
        mock_cpu.return_value = 25.0
        mock_memory.return_value = Mock(
            percent=30.0,
            used=2400000000,
            total=8000000000
        )
        mock_disk.return_value = Mock(
            used=30000000000,
            total=100000000000
        )
        
        # Mock agent manager
        mock_manager = AsyncMock()
        mock_manager.get_stats.return_value = {
            "total_agents": 2,
            "tasks_completed": 10
        }
        mock_get_manager.return_value = mock_manager
        
        response = client.get("/health/metrics")
        
        assert response.status_code == 200
        data = response.json()
        assert "system" in data
        assert "application" in data
        assert data["system"]["cpu_percent"] == 25.0
    
    def test_version(self, client):
        """Test version endpoint."""
        response = client.get("/health/version")
        
        assert response.status_code == 200
        data = response.json()
        assert "version" in data
        assert "name" in data
        assert "environment" in data


class TestErrorHandling:
    """Test error handling."""
    
    def test_404_error(self, client):
        """Test 404 error handling."""
        response = client.get("/nonexistent-endpoint")
        
        assert response.status_code == 404
    
    def test_method_not_allowed(self, client):
        """Test method not allowed error."""
        response = client.post("/")  # Root only accepts GET
        
        assert response.status_code == 405
    
    def test_validation_error(self, client):
        """Test validation error handling."""
        response = client.post(
            "/auth/login",
            json={"username": "admin"}  # Missing password
        )
        
        assert response.status_code == 422  # Validation error


class TestMiddleware:
    """Test middleware functionality."""
    
    def test_cors_headers(self, client):
        """Test CORS headers are present."""
        response = client.options("/")
        
        # CORS headers should be present
        assert "access-control-allow-origin" in response.headers
    
    def test_process_time_header(self, client):
        """Test process time header is added."""
        response = client.get("/")
        
        assert "x-process-time" in response.headers
        process_time = float(response.headers["x-process-time"])
        assert process_time >= 0


# Performance tests
class TestPerformance:
    """Test API performance."""
    
    def test_root_endpoint_performance(self, client):
        """Test root endpoint performance."""
        import time
        
        start_time = time.time()
        response = client.get("/")
        end_time = time.time()
        
        assert response.status_code == 200
        assert (end_time - start_time) < 1.0  # Should respond within 1 second
    
    def test_concurrent_requests(self, client):
        """Test handling concurrent requests."""
        import concurrent.futures
        import threading
        
        def make_request():
            return client.get("/")
        
        # Make 10 concurrent requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(make_request) for _ in range(10)]
            responses = [future.result() for future in futures]
        
        # All requests should succeed
        for response in responses:
            assert response.status_code == 200


# Integration tests
class TestAPIIntegration:
    """Integration tests for the API."""
    
    @patch('backend.agents.manager.get_agent_manager')
    def test_full_agent_workflow(self, mock_get_manager, client):
        """Test complete agent workflow."""
        # Mock agent manager
        mock_agent = Mock()
        mock_agent.get_status.return_value = {
            "agent_id": "workflow-agent",
            "name": "Workflow Agent",
            "status": "idle",
            "capabilities": [],
            "stats": {"tasks_completed": 0},
            "created_at": "2024-01-01T00:00:00",
            "last_activity": "2024-01-01T00:00:00",
        }
        mock_agent.get_response.return_value = "Agent response"
        
        mock_manager = AsyncMock()
        mock_manager.create_agent.return_value = mock_agent
        mock_manager.get_agent.return_value = mock_agent
        mock_manager.submit_task.return_value = "task-123"
        mock_manager.get_task_status.return_value = {
            "id": "task-123",
            "status": "completed",
            "result": {"analysis": "Complete"},
            "agent_id": "workflow-agent",
            "created_at": "2024-01-01T00:00:00",
        }
        mock_get_manager.return_value = mock_manager
        
        # Get auth headers
        login_response = client.post(
            "/auth/login",
            json={"username": "admin", "password": "admin123"}
        )
        token = login_response.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        
        # 1. Create agent
        create_response = client.post(
            "/agents/",
            headers=headers,
            json={"agent_type": "security_analyst", "agent_id": "workflow-agent"}
        )
        assert create_response.status_code == 200
        
        # 2. Send message to agent
        message_response = client.post(
            "/agents/workflow-agent/message",
            headers=headers,
            json="Analyze this data"
        )
        assert message_response.status_code == 200
        
        # 3. Submit task
        task_response = client.post(
            "/agents/tasks",
            headers=headers,
            json={
                "name": "Analysis Task",
                "description": "Analyze security data",
                "input_data": {"type": "log_analysis", "logs": []},
                "agent_id": "workflow-agent"
            }
        )
        assert task_response.status_code == 200
        task_id = task_response.json()["task_id"]
        
        # 4. Check task status
        status_response = client.get(f"/agents/tasks/{task_id}", headers=headers)
        assert status_response.status_code == 200
        assert status_response.json()["status"] == "completed" 