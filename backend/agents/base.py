"""Base classes for OpenAI agents in SecureML."""

import asyncio
import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Callable
from enum import Enum

import openai
from pydantic import BaseModel, Field
from langchain.schema import BaseMessage, HumanMessage, AIMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferMemory
from langchain.tools import BaseTool

from backend.core.config import get_config
from backend.core.logging import get_logger


class AgentStatus(str, Enum):
    """Agent status enumeration."""
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"


class AgentMessage(BaseModel):
    """Message model for agent communication."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    role: str  # "system", "user", "assistant", "tool"
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AgentTask(BaseModel):
    """Task model for agent execution."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    input_data: Dict[str, Any]
    priority: int = Field(default=1, ge=1, le=10)
    timeout: int = Field(default=300)  # seconds
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: AgentStatus = AgentStatus.IDLE
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class AgentCapability(BaseModel):
    """Agent capability definition."""
    name: str
    description: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    required_tools: List[str] = Field(default_factory=list)


class BaseAgent(ABC):
    """Base class for all OpenAI agents."""
    
    def __init__(
        self,
        agent_id: str,
        name: str,
        description: str,
        system_prompt: str,
        capabilities: List[AgentCapability] = None,
        tools: List[BaseTool] = None,
        max_iterations: int = 10,
        temperature: float = 0.1,
    ):
        self.agent_id = agent_id
        self.name = name
        self.description = description
        self.system_prompt = system_prompt
        self.capabilities = capabilities or []
        self.tools = tools or []
        self.max_iterations = max_iterations
        self.temperature = temperature
        
        self.config = get_config()
        self.logger = get_logger(f"agent.{agent_id}")
        
        # Initialize OpenAI client
        self.openai_client = openai.AsyncOpenAI(
            api_key=self.config.openai.api_key,
            organization=self.config.openai.organization,
        )
        
        # Initialize LangChain components
        self.llm = ChatOpenAI(
            model=self.config.openai.model,
            temperature=temperature,
            max_tokens=self.config.openai.max_tokens,
            timeout=self.config.openai.timeout,
        )
        
        self.memory = ConversationBufferMemory(
            return_messages=True,
            memory_key="chat_history"
        )
        
        # Agent state
        self.status = AgentStatus.IDLE
        self.current_task: Optional[AgentTask] = None
        self.message_history: List[AgentMessage] = []
        self.created_at = datetime.utcnow()
        self.last_activity = datetime.utcnow()
        
        # Statistics
        self.stats = {
            "tasks_completed": 0,
            "tasks_failed": 0,
            "total_tokens_used": 0,
            "average_response_time": 0.0,
        }
    
    async def execute_task(self, task: AgentTask) -> AgentTask:
        """Execute a task using the agent."""
        self.logger.info(f"Starting task execution: {task.name}")
        
        # Update task and agent status
        task.status = AgentStatus.RUNNING
        task.started_at = datetime.utcnow()
        self.status = AgentStatus.RUNNING
        self.current_task = task
        self.last_activity = datetime.utcnow()
        
        try:
            # Check timeout
            if datetime.utcnow() - task.created_at > timedelta(seconds=task.timeout):
                raise TimeoutError(f"Task {task.id} timed out")
            
            # Execute the task
            result = await self._execute_task_impl(task)
            
            # Update task with result
            task.result = result
            task.status = AgentStatus.COMPLETED
            task.completed_at = datetime.utcnow()
            self.stats["tasks_completed"] += 1
            
            self.logger.info(f"Task completed successfully: {task.name}")
            
        except Exception as e:
            self.logger.error(f"Task execution failed: {str(e)}")
            task.error = str(e)
            task.status = AgentStatus.FAILED
            task.completed_at = datetime.utcnow()
            self.stats["tasks_failed"] += 1
        
        finally:
            self.status = AgentStatus.IDLE
            self.current_task = None
            self.last_activity = datetime.utcnow()
        
        return task
    
    @abstractmethod
    async def _execute_task_impl(self, task: AgentTask) -> Dict[str, Any]:
        """Implementation-specific task execution."""
        pass
    
    async def send_message(self, content: str, role: str = "user") -> AgentMessage:
        """Send a message to the agent."""
        message = AgentMessage(
            role=role,
            content=content,
            metadata={"agent_id": self.agent_id}
        )
        
        self.message_history.append(message)
        self.memory.chat_memory.add_message(
            HumanMessage(content=content) if role == "user" else AIMessage(content=content)
        )
        
        return message
    
    async def get_response(self, message: str) -> str:
        """Get a response from the agent."""
        self.last_activity = datetime.utcnow()
        
        # Prepare messages for OpenAI
        messages = [
            {"role": "system", "content": self.system_prompt}
        ]
        
        # Add conversation history
        for msg in self.message_history[-10:]:  # Last 10 messages
            messages.append({
                "role": msg.role,
                "content": msg.content
            })
        
        # Add current message
        messages.append({
            "role": "user",
            "content": message
        })
        
        try:
            # Get response from OpenAI
            response = await self.openai_client.chat.completions.create(
                model=self.config.openai.model,
                messages=messages,
                temperature=self.temperature,
                max_tokens=self.config.openai.max_tokens,
            )
            
            response_content = response.choices[0].message.content
            self.stats["total_tokens_used"] += response.usage.total_tokens
            
            # Store response in history
            response_message = AgentMessage(
                role="assistant",
                content=response_content,
                metadata={
                    "agent_id": self.agent_id,
                    "tokens_used": response.usage.total_tokens
                }
            )
            self.message_history.append(response_message)
            
            return response_content
            
        except Exception as e:
            self.logger.error(f"Error getting response: {str(e)}")
            raise
    
    async def use_tool(self, tool_name: str, **kwargs) -> Any:
        """Use a tool by name."""
        for tool in self.tools:
            if tool.name == tool_name:
                try:
                    result = await tool.arun(**kwargs)
                    self.logger.info(f"Tool {tool_name} executed successfully")
                    return result
                except Exception as e:
                    self.logger.error(f"Tool {tool_name} execution failed: {str(e)}")
                    raise
        
        raise ValueError(f"Tool {tool_name} not found")
    
    def add_capability(self, capability: AgentCapability) -> None:
        """Add a capability to the agent."""
        self.capabilities.append(capability)
        self.logger.info(f"Added capability: {capability.name}")
    
    def add_tool(self, tool: BaseTool) -> None:
        """Add a tool to the agent."""
        self.tools.append(tool)
        self.logger.info(f"Added tool: {tool.name}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get agent status information."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "status": self.status.value,
            "current_task": self.current_task.dict() if self.current_task else None,
            "capabilities": [cap.dict() for cap in self.capabilities],
            "tools": [tool.name for tool in self.tools],
            "message_count": len(self.message_history),
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "stats": self.stats,
        }
    
    def clear_history(self) -> None:
        """Clear message history."""
        self.message_history.clear()
        self.memory.clear()
        self.logger.info("Message history cleared")


class SecurityAnalystAgent(BaseAgent):
    """Specialized agent for security analysis tasks."""
    
    def __init__(self, agent_id: str = None):
        if agent_id is None:
            agent_id = f"security_analyst_{uuid.uuid4().hex[:8]}"
        
        system_prompt = """You are a cybersecurity analyst AI agent specializing in threat detection and security analysis.
        
Your capabilities include:
- Analyzing security logs and events
- Identifying potential threats and anomalies
- Providing detailed security assessments
- Recommending remediation actions
- Correlating security events across multiple sources

You should provide clear, actionable insights and always explain your reasoning.
When analyzing security data, consider:
- Attack patterns and TTPs (Tactics, Techniques, and Procedures)
- MITRE ATT&CK framework mappings
- Risk levels and business impact
- False positive likelihood
- Recommended response actions

Always be thorough but concise in your analysis."""
        
        capabilities = [
            AgentCapability(
                name="log_analysis",
                description="Analyze security logs for threats",
                parameters={"log_types": ["syslog", "windows_event", "firewall", "ids"]}
            ),
            AgentCapability(
                name="threat_assessment",
                description="Assess threat severity and impact",
                parameters={"frameworks": ["MITRE_ATTACK", "NIST", "ISO27001"]}
            ),
            AgentCapability(
                name="incident_response",
                description="Provide incident response recommendations",
                parameters={"response_types": ["containment", "eradication", "recovery"]}
            ),
        ]
        
        super().__init__(
            agent_id=agent_id,
            name="Security Analyst Agent",
            description="AI agent specialized in cybersecurity analysis and threat detection",
            system_prompt=system_prompt,
            capabilities=capabilities,
            temperature=0.1,
        )
    
    async def _execute_task_impl(self, task: AgentTask) -> Dict[str, Any]:
        """Execute security analysis task."""
        task_type = task.input_data.get("type", "general_analysis")
        
        if task_type == "log_analysis":
            return await self._analyze_logs(task.input_data)
        elif task_type == "threat_assessment":
            return await self._assess_threat(task.input_data)
        elif task_type == "incident_response":
            return await self._generate_incident_response(task.input_data)
        else:
            return await self._general_analysis(task.input_data)
    
    async def _analyze_logs(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security logs."""
        logs = data.get("logs", [])
        log_type = data.get("log_type", "unknown")
        
        analysis_prompt = f"""Analyze the following {log_type} security logs for potential threats:

{json.dumps(logs, indent=2)}

Provide a detailed analysis including:
1. Identified threats or anomalies
2. Severity assessment (1-10 scale)
3. MITRE ATT&CK technique mappings if applicable
4. Recommended actions
5. Confidence level in the analysis

Format your response as JSON with the following structure:
{{
    "threats_identified": [...],
    "severity": 1-10,
    "mitre_techniques": [...],
    "recommendations": [...],
    "confidence": 0.0-1.0,
    "summary": "Brief summary of findings"
}}"""
        
        response = await self.get_response(analysis_prompt)
        
        try:
            # Try to parse JSON response
            result = json.loads(response)
        except json.JSONDecodeError:
            # Fallback to text response
            result = {
                "analysis": response,
                "format": "text",
                "confidence": 0.8
            }
        
        return result
    
    async def _assess_threat(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess threat severity and impact."""
        threat_data = data.get("threat_data", {})
        context = data.get("context", {})
        
        assessment_prompt = f"""Assess the following security threat:

Threat Data: {json.dumps(threat_data, indent=2)}
Context: {json.dumps(context, indent=2)}

Provide a comprehensive threat assessment including:
1. Threat classification
2. Risk level (Critical/High/Medium/Low)
3. Potential impact on business operations
4. Attack vector analysis
5. Likelihood of success
6. Recommended priority for response

Format as JSON:
{{
    "classification": "...",
    "risk_level": "...",
    "business_impact": "...",
    "attack_vectors": [...],
    "success_likelihood": 0.0-1.0,
    "response_priority": 1-10,
    "detailed_assessment": "..."
}}"""
        
        response = await self.get_response(assessment_prompt)
        
        try:
            result = json.loads(response)
        except json.JSONDecodeError:
            result = {
                "assessment": response,
                "format": "text"
            }
        
        return result
    
    async def _generate_incident_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate incident response plan."""
        incident_data = data.get("incident_data", {})
        
        response_prompt = f"""Generate an incident response plan for the following security incident:

{json.dumps(incident_data, indent=2)}

Provide a structured incident response plan including:
1. Immediate containment actions
2. Investigation steps
3. Eradication procedures
4. Recovery actions
5. Lessons learned recommendations
6. Timeline estimates for each phase

Format as JSON:
{{
    "containment": {{
        "immediate_actions": [...],
        "timeline": "...",
        "resources_needed": [...]
    }},
    "investigation": {{
        "steps": [...],
        "timeline": "...",
        "tools_required": [...]
    }},
    "eradication": {{
        "procedures": [...],
        "timeline": "...",
        "verification_steps": [...]
    }},
    "recovery": {{
        "actions": [...],
        "timeline": "...",
        "monitoring_requirements": [...]
    }},
    "lessons_learned": [...]
}}"""
        
        response = await self.get_response(response_prompt)
        
        try:
            result = json.loads(response)
        except json.JSONDecodeError:
            result = {
                "response_plan": response,
                "format": "text"
            }
        
        return result
    
    async def _general_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform general security analysis."""
        analysis_prompt = f"""Perform a general security analysis on the following data:

{json.dumps(data, indent=2)}

Provide insights, recommendations, and any security concerns you identify."""
        
        response = await self.get_response(analysis_prompt)
        
        return {
            "analysis": response,
            "timestamp": datetime.utcnow().isoformat(),
            "agent_id": self.agent_id
        } 