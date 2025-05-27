"""API routes for managing OpenAI agents."""

from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Body, Query
from pydantic import BaseModel, Field

from backend.core.logging import get_logger
from backend.agents.manager import get_agent_manager, AgentManager
from backend.agents.base import AgentTask, AgentCapability

router = APIRouter()
logger = get_logger("api.agents")


# Pydantic models for API
class CreateAgentRequest(BaseModel):
    """Request model for creating an agent."""
    agent_type: str = Field(..., description="Type of agent to create")
    agent_id: Optional[str] = Field(None, description="Custom agent ID")
    name: Optional[str] = Field(None, description="Custom agent name")
    description: Optional[str] = Field(None, description="Agent description")


class AgentResponse(BaseModel):
    """Response model for agent information."""
    agent_id: str
    name: str
    status: str
    capabilities: List[Dict[str, Any]]
    stats: Dict[str, Any]
    created_at: str
    last_activity: str


class CreateTaskRequest(BaseModel):
    """Request model for creating a task."""
    name: str = Field(..., description="Task name")
    description: str = Field(..., description="Task description")
    input_data: Dict[str, Any] = Field(..., description="Task input data")
    priority: int = Field(default=1, ge=1, le=10, description="Task priority")
    timeout: int = Field(default=300, description="Task timeout in seconds")
    agent_id: Optional[str] = Field(None, description="Specific agent ID")
    agent_type: Optional[str] = Field(None, description="Agent type if no specific agent")


class TaskResponse(BaseModel):
    """Response model for task information."""
    id: str
    name: str
    status: str
    result: Optional[Dict[str, Any]]
    error: Optional[str]
    agent_id: Optional[str]
    created_at: str
    started_at: Optional[str]
    completed_at: Optional[str]


class MessageRequest(BaseModel):
    """Request model for sending messages to agents."""
    message: str = Field(..., description="Message content")
    agent_type: Optional[str] = Field(None, description="Filter by agent type")


@router.get("/", response_model=List[AgentResponse])
async def list_agents(
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> List[AgentResponse]:
    """List all agents and their status."""
    try:
        agents_data = agent_manager.list_agents()
        
        agents = []
        for agent_data in agents_data:
            agents.append(AgentResponse(
                agent_id=agent_data["agent_id"],
                name=agent_data["name"],
                status=agent_data["status"],
                capabilities=agent_data["capabilities"],
                stats=agent_data["stats"],
                created_at=agent_data["created_at"],
                last_activity=agent_data["last_activity"],
            ))
        
        return agents
        
    except Exception as e:
        logger.error(f"Error listing agents: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/", response_model=AgentResponse)
async def create_agent(
    request: CreateAgentRequest,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> AgentResponse:
    """Create a new agent."""
    try:
        agent = agent_manager.create_agent(
            agent_type=request.agent_type,
            agent_id=request.agent_id,
        )
        
        agent_data = agent.get_status()
        
        return AgentResponse(
            agent_id=agent_data["agent_id"],
            name=agent_data["name"],
            status=agent_data["status"],
            capabilities=agent_data["capabilities"],
            stats=agent_data["stats"],
            created_at=agent_data["created_at"],
            last_activity=agent_data["last_activity"],
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating agent: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> AgentResponse:
    """Get agent details by ID."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent_data = agent.get_status()
        
        return AgentResponse(
            agent_id=agent_data["agent_id"],
            name=agent_data["name"],
            status=agent_data["status"],
            capabilities=agent_data["capabilities"],
            stats=agent_data["stats"],
            created_at=agent_data["created_at"],
            last_activity=agent_data["last_activity"],
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, str]:
    """Delete an agent."""
    try:
        success = agent_manager.remove_agent(agent_id)
        if not success:
            raise HTTPException(status_code=404, detail="Agent not found or cannot be removed")
        
        return {"message": f"Agent {agent_id} deleted successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/tasks", response_model=Dict[str, str])
async def create_task(
    request: CreateTaskRequest,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, str]:
    """Submit a task for execution."""
    try:
        task = AgentTask(
            name=request.name,
            description=request.description,
            input_data=request.input_data,
            priority=request.priority,
            timeout=request.timeout,
        )
        
        task_id = await agent_manager.submit_task(
            task=task,
            agent_id=request.agent_id,
            agent_type=request.agent_type,
        )
        
        return {"task_id": task_id, "message": "Task submitted successfully"}
        
    except Exception as e:
        logger.error(f"Error creating task: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}", response_model=TaskResponse)
async def get_task_status(
    task_id: str,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> TaskResponse:
    """Get task status and results."""
    try:
        task_data = await agent_manager.get_task_status(task_id)
        if not task_data:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return TaskResponse(
            id=task_data["id"],
            name=task_data.get("name", "Unknown"),
            status=task_data["status"],
            result=task_data.get("result"),
            error=task_data.get("error"),
            agent_id=task_data.get("agent_id"),
            created_at=task_data.get("created_at", ""),
            started_at=task_data.get("started_at"),
            completed_at=task_data.get("completed_at"),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting task status {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/tasks/{task_id}")
async def cancel_task(
    task_id: str,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, str]:
    """Cancel a task."""
    try:
        success = await agent_manager.cancel_task(task_id)
        if not success:
            raise HTTPException(status_code=404, detail="Task not found or cannot be cancelled")
        
        return {"message": f"Task {task_id} cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling task {task_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/broadcast", response_model=Dict[str, str])
async def broadcast_message(
    request: MessageRequest,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, str]:
    """Broadcast a message to all agents or agents of a specific type."""
    try:
        responses = await agent_manager.broadcast_message(
            message=request.message,
            agent_type=request.agent_type,
        )
        
        return responses
        
    except Exception as e:
        logger.error(f"Error broadcasting message: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/manager")
async def get_manager_stats(
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, Any]:
    """Get agent manager statistics."""
    try:
        return agent_manager.get_stats()
        
    except Exception as e:
        logger.error(f"Error getting manager stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health/check")
async def health_check(
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, Any]:
    """Perform health check on all agents."""
    try:
        return await agent_manager.health_check()
        
    except Exception as e:
        logger.error(f"Error performing health check: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_id}/message")
async def send_message_to_agent(
    agent_id: str,
    message: str = Body(..., embed=True),
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, str]:
    """Send a message to a specific agent."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        response = await agent.get_response(message)
        
        return {"response": response}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending message to agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{agent_id}/clear-history")
async def clear_agent_history(
    agent_id: str,
    agent_manager: AgentManager = Depends(get_agent_manager)
) -> Dict[str, str]:
    """Clear an agent's conversation history."""
    try:
        agent = agent_manager.get_agent(agent_id)
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        agent.clear_history()
        
        return {"message": f"History cleared for agent {agent_id}"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error clearing history for agent {agent_id}: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e)) 