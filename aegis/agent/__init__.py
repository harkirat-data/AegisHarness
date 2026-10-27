"""
AegisHarness Autonomous Agent Subsystem
"""
from aegis.agent.controller import AutonomousAgentController
from aegis.agent.llm_client import LocalLLMClient
from aegis.agent.schemas import AgentExecutionReport, AgentOutcomeType, ToolCallRequest, ToolResult
from aegis.agent.tools import ControlledToolRegistry

__all__ = [
    "AutonomousAgentController",
    "LocalLLMClient",
    "ControlledToolRegistry",
    "ToolCallRequest",
    "ToolResult",
    "AgentOutcomeType",
    "AgentExecutionReport",
]
