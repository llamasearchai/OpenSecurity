"""Agent manager for orchestrating OpenAI agents in SecureML."""

import asyncio
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Type, Union
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from backend.core.config import get_config
from backend.core.logging import get_logger
from backend.agents.base import BaseAgent, AgentTask, AgentStatus, SecurityAnalystAgent


class AgentManager:
    """Manager for orchestrating multiple OpenAI agents."""
    
    def __init__(self, max_concurrent_agents: int = None):
        self.config = get_config()
        self.logger = get_logger("agent_manager")
        
        self.max_concurrent_agents = (
            max_concurrent_agents or self.config.agents.max_concurrent_agents
        )
        
        # Agent registry
        self.agents: Dict[str, BaseAgent] = {}
        self.agent_types: Dict[str, Type[BaseAgent]] = {
            "security_analyst": SecurityAnalystAgent,
        }
        
        # Task management
        self.task_queue: List[AgentTask] = []
        self.running_tasks: Dict[str, AgentTask] = {}
        self.completed_tasks: Dict[str, AgentTask] = {}
        
        # Statistics
        self.stats = {
            "agents_created": 0,
            "tasks_queued": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "total_execution_time": 0.0,
        }
        
        # Background task for processing queue
        self._processing_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()
        
        self.logger.info("Agent manager initialized")
    
    async def start(self) -> None:
        """Start the agent manager."""
        if self._processing_task is None:
            self._processing_task = asyncio.create_task(self._process_task_queue())
            self.logger.info("Agent manager started")
    
    async def stop(self) -> None:
        """Stop the agent manager."""
        self._shutdown_event.set()
        
        if self._processing_task:
            await self._processing_task
            self._processing_task = None
        
        # Stop all running agents
        for agent in self.agents.values():
            if agent.status == AgentStatus.RUNNING:
                agent.status = AgentStatus.IDLE
        
        self.logger.info("Agent manager stopped")
    
    def create_agent(
        self,
        agent_type: str,
        agent_id: str = None,
        **kwargs
    ) -> BaseAgent:
        """Create a new agent of the specified type."""
        if agent_type not in self.agent_types:
            raise ValueError(f"Unknown agent type: {agent_type}")
        
        if agent_id is None:
            agent_id = f"{agent_type}_{uuid.uuid4().hex[:8]}"
        
        if agent_id in self.agents:
            raise ValueError(f"Agent with ID {agent_id} already exists")
        
        agent_class = self.agent_types[agent_type]
        agent = agent_class(agent_id=agent_id, **kwargs)
        
        self.agents[agent_id] = agent
        self.stats["agents_created"] += 1
        
        self.logger.info(f"Created agent: {agent_id} ({agent_type})")
        return agent
    
    def get_agent(self, agent_id: str) -> Optional[BaseAgent]:
        """Get an agent by ID."""
        return self.agents.get(agent_id)
    
    def list_agents(self) -> List[Dict[str, Any]]:
        """List all agents and their status."""
        return [agent.get_status() for agent in self.agents.values()]
    
    def remove_agent(self, agent_id: str) -> bool:
        """Remove an agent."""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            if agent.status == AgentStatus.RUNNING:
                self.logger.warning(f"Cannot remove running agent: {agent_id}")
                return False
            
            del self.agents[agent_id]
            self.logger.info(f"Removed agent: {agent_id}")
            return True
        
        return False
    
    async def submit_task(
        self,
        task: AgentTask,
        agent_id: str = None,
        agent_type: str = None
    ) -> str:
        """Submit a task for execution."""
        # Assign agent if not specified
        if agent_id is None:
            if agent_type is None:
                agent_type = "security_analyst"  # Default agent type
            
            # Find or create an available agent
            agent_id = await self._get_or_create_agent(agent_type)
        
        # Validate agent exists
        if agent_id not in self.agents:
            raise ValueError(f"Agent {agent_id} not found")
        
        # Add task to queue
        task.metadata = task.metadata or {}
        task.metadata["assigned_agent"] = agent_id
        
        self.task_queue.append(task)
        self.stats["tasks_queued"] += 1
        
        self.logger.info(f"Task {task.id} queued for agent {agent_id}")
        return task.id
    
    async def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a task."""
        # Check running tasks
        if task_id in self.running_tasks:
            task = self.running_tasks[task_id]
            return {
                "id": task.id,
                "status": task.status.value,
                "progress": "running",
                "agent_id": task.metadata.get("assigned_agent"),
                "started_at": task.started_at.isoformat() if task.started_at else None,
            }
        
        # Check completed tasks
        if task_id in self.completed_tasks:
            task = self.completed_tasks[task_id]
            return {
                "id": task.id,
                "status": task.status.value,
                "result": task.result,
                "error": task.error,
                "agent_id": task.metadata.get("assigned_agent"),
                "started_at": task.started_at.isoformat() if task.started_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            }
        
        # Check queued tasks
        for task in self.task_queue:
            if task.id == task_id:
                return {
                    "id": task.id,
                    "status": "queued",
                    "position": self.task_queue.index(task),
                    "agent_id": task.metadata.get("assigned_agent"),
                }
        
        return None
    
    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a task."""
        # Remove from queue if not started
        for i, task in enumerate(self.task_queue):
            if task.id == task_id:
                del self.task_queue[i]
                self.logger.info(f"Cancelled queued task: {task_id}")
                return True
        
        # Cannot cancel running tasks (would need more complex implementation)
        if task_id in self.running_tasks:
            self.logger.warning(f"Cannot cancel running task: {task_id}")
            return False
        
        return False
    
    async def _get_or_create_agent(self, agent_type: str) -> str:
        """Get an available agent or create a new one."""
        # Find idle agent of the specified type
        for agent_id, agent in self.agents.items():
            if (agent.status == AgentStatus.IDLE and 
                agent.__class__.__name__.lower().replace("agent", "") == agent_type.replace("_", "")):
                return agent_id
        
        # Create new agent if under limit
        if len(self.agents) < self.max_concurrent_agents:
            agent = self.create_agent(agent_type)
            return agent.agent_id
        
        # Wait for an agent to become available
        while True:
            for agent_id, agent in self.agents.items():
                if agent.status == AgentStatus.IDLE:
                    return agent_id
            
            await asyncio.sleep(1)  # Wait before checking again
    
    async def _process_task_queue(self) -> None:
        """Background task to process the task queue."""
        self.logger.info("Started task queue processing")
        
        while not self._shutdown_event.is_set():
            try:
                # Process tasks if queue is not empty and we have capacity
                if (self.task_queue and 
                    len(self.running_tasks) < self.max_concurrent_agents):
                    
                    # Get next task (priority-based)
                    task = self._get_next_task()
                    if task:
                        await self._execute_task(task)
                
                # Clean up completed tasks (keep last 100)
                if len(self.completed_tasks) > 100:
                    oldest_tasks = sorted(
                        self.completed_tasks.items(),
                        key=lambda x: x[1].completed_at or datetime.min
                    )
                    for task_id, _ in oldest_tasks[:-100]:
                        del self.completed_tasks[task_id]
                
                await asyncio.sleep(0.1)  # Small delay to prevent busy waiting
                
            except Exception as e:
                self.logger.error(f"Error in task queue processing: {str(e)}")
                await asyncio.sleep(1)
        
        self.logger.info("Task queue processing stopped")
    
    def _get_next_task(self) -> Optional[AgentTask]:
        """Get the next task from the queue based on priority."""
        if not self.task_queue:
            return None
        
        # Sort by priority (higher number = higher priority) and creation time
        self.task_queue.sort(
            key=lambda t: (-t.priority, t.created_at)
        )
        
        return self.task_queue.pop(0)
    
    async def _execute_task(self, task: AgentTask) -> None:
        """Execute a task using the assigned agent."""
        agent_id = task.metadata.get("assigned_agent")
        if not agent_id or agent_id not in self.agents:
            self.logger.error(f"Invalid agent assignment for task {task.id}")
            task.status = AgentStatus.FAILED
            task.error = "Invalid agent assignment"
            self.completed_tasks[task.id] = task
            return
        
        agent = self.agents[agent_id]
        
        # Move task to running
        self.running_tasks[task.id] = task
        
        try:
            # Execute task
            start_time = datetime.utcnow()
            completed_task = await agent.execute_task(task)
            end_time = datetime.utcnow()
            
            # Update statistics
            execution_time = (end_time - start_time).total_seconds()
            self.stats["total_execution_time"] += execution_time
            
            if completed_task.status == AgentStatus.COMPLETED:
                self.stats["tasks_completed"] += 1
            else:
                self.stats["tasks_failed"] += 1
            
            # Move to completed
            self.completed_tasks[task.id] = completed_task
            
            self.logger.info(
                f"Task {task.id} completed in {execution_time:.2f}s "
                f"with status {completed_task.status.value}"
            )
            
        except Exception as e:
            self.logger.error(f"Task execution failed: {str(e)}")
            task.status = AgentStatus.FAILED
            task.error = str(e)
            task.completed_at = datetime.utcnow()
            self.completed_tasks[task.id] = task
            self.stats["tasks_failed"] += 1
        
        finally:
            # Remove from running tasks
            if task.id in self.running_tasks:
                del self.running_tasks[task.id]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        active_agents = sum(1 for agent in self.agents.values() 
                          if agent.status != AgentStatus.IDLE)
        
        return {
            "total_agents": len(self.agents),
            "active_agents": active_agents,
            "queued_tasks": len(self.task_queue),
            "running_tasks": len(self.running_tasks),
            "completed_tasks": len(self.completed_tasks),
            "max_concurrent_agents": self.max_concurrent_agents,
            **self.stats,
            "average_execution_time": (
                self.stats["total_execution_time"] / max(1, self.stats["tasks_completed"])
            ),
        }
    
    async def broadcast_message(self, message: str, agent_type: str = None) -> Dict[str, str]:
        """Broadcast a message to all agents or agents of a specific type."""
        responses = {}
        
        for agent_id, agent in self.agents.items():
            if agent_type is None or agent.__class__.__name__.lower().startswith(agent_type):
                try:
                    response = await agent.get_response(message)
                    responses[agent_id] = response
                except Exception as e:
                    self.logger.error(f"Error getting response from agent {agent_id}: {str(e)}")
                    responses[agent_id] = f"Error: {str(e)}"
        
        return responses
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all agents."""
        health_status = {
            "manager_status": "healthy",
            "agents": {},
            "issues": []
        }
        
        for agent_id, agent in self.agents.items():
            try:
                # Check if agent is responsive
                if datetime.utcnow() - agent.last_activity > timedelta(minutes=30):
                    health_status["issues"].append(f"Agent {agent_id} inactive for >30 minutes")
                
                agent_health = {
                    "status": agent.status.value,
                    "last_activity": agent.last_activity.isoformat(),
                    "tasks_completed": agent.stats["tasks_completed"],
                    "tasks_failed": agent.stats["tasks_failed"],
                }
                
                health_status["agents"][agent_id] = agent_health
                
            except Exception as e:
                health_status["issues"].append(f"Health check failed for agent {agent_id}: {str(e)}")
        
        if health_status["issues"]:
            health_status["manager_status"] = "degraded"
        
        return health_status


# Global agent manager instance
agent_manager = AgentManager()


async def get_agent_manager() -> AgentManager:
    """Get the global agent manager instance."""
    if agent_manager._processing_task is None:
        await agent_manager.start()
    return agent_manager 