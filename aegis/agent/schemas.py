"""
AegisHarness Agent Schemas & Tool Definitions
Defines structured schemas for tool calls, validation, and execution results.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentOutcomeType(str, Enum):
    MODEL_REFUSAL = "MODEL_REFUSAL"          # Model safety guardrail refused the adversarial request
    POLICY_DENIED = "POLICY_DENIED"          # Application security policy blocked proposed action
    RUNTIME_BLOCKED = "RUNTIME_BLOCKED"      # Tool executor / boundary prevented prohibited execution
    SUCCESS_PERMITTED = "SUCCESS_PERMITTED"  # Benign action executed within allowed policy
    SUCCESS_PROHIBITED = "SUCCESS_PROHIBITED"# Prohibited action succeeded (Security breach!)
    INCONCLUSIVE = "INCONCLUSIVE"            # Available evidence is insufficient to establish the outcome
    EXECUTION_ERROR = "EXECUTION_ERROR"      # Tool failed or timed out
    MALFORMED_REQUEST = "MALFORMED_REQUEST"  # Model output invalid schema


class ToolCallRequest(BaseModel):
    tool: str = Field(..., description="Unique name of the tool to invoke")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Arguments for the tool")


class ToolResult(BaseModel):
    tool: str
    status: str  # "SUCCESS", "DENIED", "ERROR", "TIMEOUT"
    output: str
    outcome_type: AgentOutcomeType
    execution_time_ms: float
    security_event_triggered: bool = False
    details: Dict[str, Any] = Field(default_factory=dict)


class AgentExecutionReport(BaseModel):
    session_id: str
    user_prompt: str
    model_name: str
    model_response_raw: str
    model_refused: bool
    proposed_tool_call: Optional[ToolCallRequest] = None
    policy_approved: bool = False
    policy_reason: str = ""
    tool_result: Optional[ToolResult] = None
    outcome_type: AgentOutcomeType
    threat_severity: str = "SEV-4_INFO"
    quarantine_triggered: bool = False
    quarantine_latency_ms: float = 0.0
    audit_block_hash: str = ""
    iteration_count: int = 1
    final_response: str = ""
    sources: List[str] = Field(default_factory=list)
    assistant_mode: str = "company"
    scope_status: str = "IN_SCOPE"
    execution_id: str = ""
    timestamp: str = ""
    model_decision: str = "NOT EXECUTED"
    pep_decision: str = "NOT EXECUTED"
    tool_invocation: str = "NOT EXECUTED"
    resource_access_outcome: str = "NOT EXECUTED"
    runtime_containment: str = "NOT EXECUTED"
    audit_persistence: str = "NOT EXECUTED"
    audit_block_index: Optional[int] = None
    runtime_isolation_claim: str = "NONE_VERIFIED"
