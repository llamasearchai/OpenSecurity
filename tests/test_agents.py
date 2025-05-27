"""Tests for the OpenAI agents system."""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch
from datetime import datetime

from backend.agents.base import (
    BaseAgent, SecurityAnalystAgent, AgentTask, AgentStatus, 
    AgentMessage, AgentCapability
)
from backend.agents.manager import AgentManager


class TestBaseAgent:
    """Test the base agent functionality."""
    
    @pytest.mark.asyncio
    async def test_agent_initialization(self, mock_openai_client):
        """Test agent initialization."""
        agent = SecurityAnalystAgent("test-agent")
        agent.openai_client = mock_openai_client
        
        assert agent.agent_id == "test-agent"
        assert agent.name == "Security Analyst Agent"
        assert agent.status == AgentStatus.IDLE
        assert len(agent.capabilities) > 0
        assert agent.stats["tasks_completed"] == 0
    
    @pytest.mark.asyncio
    async def test_agent_message_handling(self, security_agent):
        """Test agent message handling."""
        message = await security_agent.send_message("Test message", "user")
        
        assert message.role == "user"
        assert message.content == "Test message"
        assert message.metadata["agent_id"] == security_agent.agent_id
        assert len(security_agent.message_history) == 1
    
    @pytest.mark.asyncio
    async def test_agent_response_generation(self, security_agent):
        """Test agent response generation."""
        response = await security_agent.get_response("Analyze this security event")
        
        assert isinstance(response, str)
        assert response == "Test response from AI agent"
        assert len(security_agent.message_history) == 2  # User message + AI response
    
    @pytest.mark.asyncio
    async def test_agent_task_execution(self, security_agent, sample_log_data):
        """Test agent task execution."""
        task = AgentTask(
            name="Log Analysis",
            description="Analyze security logs",
            input_data=sample_log_data,
        )
        
        completed_task = await security_agent.execute_task(task)
        
        assert completed_task.status == AgentStatus.COMPLETED
        assert completed_task.result is not None
        assert completed_task.started_at is not None
        assert completed_task.completed_at is not None
        assert security_agent.stats["tasks_completed"] == 1
    
    @pytest.mark.asyncio
    async def test_agent_task_timeout(self, security_agent):
        """Test agent task timeout handling."""
        # Create a task that's already expired
        task = AgentTask(
            name="Timeout Test",
            description="Test timeout",
            input_data={"type": "test"},
            timeout=1,  # 1 second timeout
        )
        
        # Simulate task being old
        task.created_at = datetime.utcnow().replace(year=2020)
        
        completed_task = await security_agent.execute_task(task)
        
        assert completed_task.status == AgentStatus.FAILED
        assert "timed out" in completed_task.error.lower()
    
    def test_agent_capability_management(self, security_agent):
        """Test agent capability management."""
        initial_count = len(security_agent.capabilities)
        
        new_capability = AgentCapability(
            name="test_capability",
            description="Test capability",
            parameters={"test": True},
        )
        
        security_agent.add_capability(new_capability)
        
        assert len(security_agent.capabilities) == initial_count + 1
        assert security_agent.capabilities[-1].name == "test_capability"
    
    def test_agent_status_reporting(self, security_agent):
        """Test agent status reporting."""
        status = security_agent.get_status()
        
        assert status["agent_id"] == security_agent.agent_id
        assert status["name"] == security_agent.name
        assert status["status"] == AgentStatus.IDLE.value
        assert "capabilities" in status
        assert "stats" in status
        assert "created_at" in status
    
    def test_agent_history_clearing(self, security_agent):
        """Test agent history clearing."""
        # Add some messages
        asyncio.run(security_agent.send_message("Test 1", "user"))
        asyncio.run(security_agent.send_message("Test 2", "user"))
        
        assert len(security_agent.message_history) == 2
        
        security_agent.clear_history()
        
        assert len(security_agent.message_history) == 0


class TestSecurityAnalystAgent:
    """Test the security analyst agent specifically."""
    
    @pytest.mark.asyncio
    async def test_log_analysis_task(self, security_agent, sample_log_data):
        """Test log analysis functionality."""
        task = AgentTask(
            name="Log Analysis",
            description="Analyze firewall logs",
            input_data={
                "type": "log_analysis",
                **sample_log_data,
            },
        )
        
        completed_task = await security_agent.execute_task(task)
        
        assert completed_task.status == AgentStatus.COMPLETED
        assert completed_task.result is not None
        
        # Check if result contains expected analysis fields
        result = completed_task.result
        assert "analysis" in result or "threats_identified" in result
    
    @pytest.mark.asyncio
    async def test_threat_assessment_task(self, security_agent, sample_threat_data):
        """Test threat assessment functionality."""
        task = AgentTask(
            name="Threat Assessment",
            description="Assess threat severity",
            input_data={
                "type": "threat_assessment",
                **sample_threat_data,
            },
        )
        
        completed_task = await security_agent.execute_task(task)
        
        assert completed_task.status == AgentStatus.COMPLETED
        assert completed_task.result is not None
    
    @pytest.mark.asyncio
    async def test_incident_response_task(self, security_agent, sample_incident_data):
        """Test incident response functionality."""
        task = AgentTask(
            name="Incident Response",
            description="Generate incident response plan",
            input_data={
                "type": "incident_response",
                **sample_incident_data,
            },
        )
        
        completed_task = await security_agent.execute_task(task)
        
        assert completed_task.status == AgentStatus.COMPLETED
        assert completed_task.result is not None
    
    @pytest.mark.asyncio
    async def test_general_analysis_task(self, security_agent):
        """Test general analysis functionality."""
        task = AgentTask(
            name="General Analysis",
            description="General security analysis",
            input_data={
                "type": "general_analysis",
                "data": {"test": "data"},
            },
        )
        
        completed_task = await security_agent.execute_task(task)
        
        assert completed_task.status == AgentStatus.COMPLETED
        assert completed_task.result is not None
        assert "analysis" in completed_task.result


class TestAgentManager:
    """Test the agent manager functionality."""
    
    @pytest.mark.asyncio
    async def test_manager_initialization(self):
        """Test agent manager initialization."""
        manager = AgentManager(max_concurrent_agents=5)
        
        assert manager.max_concurrent_agents == 5
        assert len(manager.agents) == 0
        assert len(manager.task_queue) == 0
        assert manager.stats["agents_created"] == 0
    
    @pytest.mark.asyncio
    async def test_agent_creation(self, agent_manager):
        """Test agent creation through manager."""
        agent = agent_manager.create_agent("security_analyst", "test-agent-1")
        
        assert agent.agent_id == "test-agent-1"
        assert "test-agent-1" in agent_manager.agents
        assert agent_manager.stats["agents_created"] == 1
    
    @pytest.mark.asyncio
    async def test_duplicate_agent_creation(self, agent_manager):
        """Test duplicate agent creation prevention."""
        agent_manager.create_agent("security_analyst", "test-agent-1")
        
        with pytest.raises(ValueError, match="already exists"):
            agent_manager.create_agent("security_analyst", "test-agent-1")
    
    @pytest.mark.asyncio
    async def test_invalid_agent_type(self, agent_manager):
        """Test invalid agent type handling."""
        with pytest.raises(ValueError, match="Unknown agent type"):
            agent_manager.create_agent("invalid_type")
    
    @pytest.mark.asyncio
    async def test_agent_retrieval(self, agent_manager):
        """Test agent retrieval."""
        agent = agent_manager.create_agent("security_analyst", "test-agent-1")
        
        retrieved_agent = agent_manager.get_agent("test-agent-1")
        assert retrieved_agent is agent
        
        non_existent = agent_manager.get_agent("non-existent")
        assert non_existent is None
    
    @pytest.mark.asyncio
    async def test_agent_removal(self, agent_manager):
        """Test agent removal."""
        agent_manager.create_agent("security_analyst", "test-agent-1")
        
        success = agent_manager.remove_agent("test-agent-1")
        assert success is True
        assert "test-agent-1" not in agent_manager.agents
        
        # Try to remove non-existent agent
        success = agent_manager.remove_agent("non-existent")
        assert success is False
    
    @pytest.mark.asyncio
    async def test_task_submission(self, agent_manager, sample_agent_task):
        """Test task submission."""
        # Create an agent first
        agent_manager.create_agent("security_analyst", "test-agent-1")
        
        task_id = await agent_manager.submit_task(
            sample_agent_task,
            agent_id="test-agent-1"
        )
        
        assert task_id == sample_agent_task.id
        assert agent_manager.stats["tasks_queued"] == 1
    
    @pytest.mark.asyncio
    async def test_task_status_tracking(self, agent_manager, sample_agent_task):
        """Test task status tracking."""
        agent_manager.create_agent("security_analyst", "test-agent-1")
        
        task_id = await agent_manager.submit_task(
            sample_agent_task,
            agent_id="test-agent-1"
        )
        
        # Check initial status (queued)
        status = await agent_manager.get_task_status(task_id)
        assert status is not None
        assert status["id"] == task_id
        assert status["status"] in ["queued", "running", "completed"]
    
    @pytest.mark.asyncio
    async def test_task_cancellation(self, agent_manager, sample_agent_task):
        """Test task cancellation."""
        agent_manager.create_agent("security_analyst", "test-agent-1")
        
        task_id = await agent_manager.submit_task(
            sample_agent_task,
            agent_id="test-agent-1"
        )
        
        # Cancel the task immediately (before it starts)
        success = await agent_manager.cancel_task(task_id)
        assert success is True
    
    @pytest.mark.asyncio
    async def test_manager_statistics(self, agent_manager):
        """Test manager statistics."""
        # Create some agents
        agent_manager.create_agent("security_analyst", "agent-1")
        agent_manager.create_agent("security_analyst", "agent-2")
        
        stats = agent_manager.get_stats()
        
        assert stats["total_agents"] == 2
        assert stats["agents_created"] == 2
        assert stats["queued_tasks"] == 0
        assert stats["running_tasks"] == 0
    
    @pytest.mark.asyncio
    async def test_broadcast_message(self, agent_manager, mock_openai_client):
        """Test broadcasting messages to agents."""
        # Create agents and mock their OpenAI clients
        agent1 = agent_manager.create_agent("security_analyst", "agent-1")
        agent2 = agent_manager.create_agent("security_analyst", "agent-2")
        
        agent1.openai_client = mock_openai_client
        agent2.openai_client = mock_openai_client
        
        responses = await agent_manager.broadcast_message("Test broadcast")
        
        assert len(responses) == 2
        assert "agent-1" in responses
        assert "agent-2" in responses
    
    @pytest.mark.asyncio
    async def test_health_check(self, agent_manager):
        """Test agent manager health check."""
        agent_manager.create_agent("security_analyst", "agent-1")
        
        health = await agent_manager.health_check()
        
        assert "manager_status" in health
        assert "agents" in health
        assert "issues" in health
        assert "agent-1" in health["agents"]


class TestAgentTask:
    """Test agent task functionality."""
    
    def test_task_creation(self):
        """Test task creation."""
        task = AgentTask(
            name="Test Task",
            description="A test task",
            input_data={"test": "data"},
            priority=5,
            timeout=300,
        )
        
        assert task.name == "Test Task"
        assert task.description == "A test task"
        assert task.priority == 5
        assert task.timeout == 300
        assert task.status == AgentStatus.IDLE
        assert task.result is None
        assert task.error is None
    
    def test_task_validation(self):
        """Test task validation."""
        # Test priority validation
        with pytest.raises(ValueError):
            AgentTask(
                name="Test",
                description="Test",
                input_data={},
                priority=11,  # Invalid priority
            )
        
        with pytest.raises(ValueError):
            AgentTask(
                name="Test",
                description="Test",
                input_data={},
                priority=0,  # Invalid priority
            )


class TestAgentMessage:
    """Test agent message functionality."""
    
    def test_message_creation(self):
        """Test message creation."""
        message = AgentMessage(
            role="user",
            content="Test message",
            metadata={"test": "data"},
        )
        
        assert message.role == "user"
        assert message.content == "Test message"
        assert message.metadata["test"] == "data"
        assert message.id is not None
        assert message.timestamp is not None


class TestAgentCapability:
    """Test agent capability functionality."""
    
    def test_capability_creation(self):
        """Test capability creation."""
        capability = AgentCapability(
            name="test_capability",
            description="A test capability",
            parameters={"param1": "value1"},
            required_tools=["tool1", "tool2"],
        )
        
        assert capability.name == "test_capability"
        assert capability.description == "A test capability"
        assert capability.parameters["param1"] == "value1"
        assert "tool1" in capability.required_tools
        assert "tool2" in capability.required_tools


# Integration tests
class TestAgentIntegration:
    """Integration tests for the agent system."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_task_execution(self, mock_openai_client):
        """Test end-to-end task execution."""
        # Create manager and agent
        manager = AgentManager(max_concurrent_agents=1)
        await manager.start()
        
        try:
            agent = manager.create_agent("security_analyst", "test-agent")
            agent.openai_client = mock_openai_client
            
            # Submit task
            task = AgentTask(
                name="Integration Test",
                description="End-to-end test",
                input_data={
                    "type": "log_analysis",
                    "logs": [{"test": "log"}],
                    "log_type": "test",
                },
            )
            
            task_id = await manager.submit_task(task, agent_id="test-agent")
            
            # Wait for completion (with timeout)
            max_wait = 10  # seconds
            wait_time = 0
            while wait_time < max_wait:
                status = await manager.get_task_status(task_id)
                if status["status"] in ["completed", "failed"]:
                    break
                await asyncio.sleep(0.1)
                wait_time += 0.1
            
            # Check final status
            final_status = await manager.get_task_status(task_id)
            assert final_status["status"] == "completed"
            assert final_status["result"] is not None
            
        finally:
            await manager.stop()
    
    @pytest.mark.asyncio
    async def test_concurrent_task_execution(self, mock_openai_client):
        """Test concurrent task execution."""
        manager = AgentManager(max_concurrent_agents=2)
        await manager.start()
        
        try:
            # Create multiple agents
            agent1 = manager.create_agent("security_analyst", "agent-1")
            agent2 = manager.create_agent("security_analyst", "agent-2")
            
            agent1.openai_client = mock_openai_client
            agent2.openai_client = mock_openai_client
            
            # Submit multiple tasks
            tasks = []
            for i in range(3):
                task = AgentTask(
                    name=f"Concurrent Test {i}",
                    description=f"Concurrent test task {i}",
                    input_data={"type": "general_analysis", "data": {"test": i}},
                )
                task_id = await manager.submit_task(task)
                tasks.append(task_id)
            
            # Wait for all tasks to complete
            max_wait = 15  # seconds
            wait_time = 0
            while wait_time < max_wait:
                statuses = []
                for task_id in tasks:
                    status = await manager.get_task_status(task_id)
                    statuses.append(status["status"])
                
                if all(s in ["completed", "failed"] for s in statuses):
                    break
                
                await asyncio.sleep(0.1)
                wait_time += 0.1
            
            # Check all tasks completed
            for task_id in tasks:
                status = await manager.get_task_status(task_id)
                assert status["status"] in ["completed", "failed"]
            
        finally:
            await manager.stop() 