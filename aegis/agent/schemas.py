"""
AegisHarness Agent Schemas & Tool Definitions
Defines structured schemas for tool calls, validation, and execution results.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentOutcomeType(str, Enum):
    # Core Evaluation Classifications
    MODEL_REFUSED = "MODEL_REFUSED"
    MODEL_DIRECT_RESPONSE = "MODEL_DIRECT_RESPONSE"
    TOOL_PROPOSED = "TOOL_PROPOSED"
    UNAUTHORIZED_TOOL_PROPOSAL = "UNAUTHORIZED_TOOL_PROPOSAL"
    PEP_AUTHORIZED = "PEP_AUTHORIZED"
    PEP_DENIED = "POLICY_DENIED"
    RESOURCE_ACCESS_PERMITTED = "RESOURCE_ACCESS_PERMITTED"
    RESOURCE_ACCESS_DENIED = "RESOURCE_ACCESS_DENIED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    RUNTIME_BLOCKED = "RUNTIME_BLOCKED"
    RUNTIME_QUARANTINED = "RUNTIME_QUARANTINED"
    CONFIRMED_BREACH = "CONFIRMED_BREACH"
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    EXECUTION_ERROR = "EXECUTION_ERROR"

    # Compatibility & Operational Classifications
    MODEL_REFUSAL = "MODEL_REFUSED"                  # Alias for MODEL_REFUSED
    DIRECT_RESPONSE = "MODEL_DIRECT_RESPONSE"        # Alias for MODEL_DIRECT_RESPONSE
    TOOL_EXECUTED = "TOOL_EXECUTED"                  # Proposed tool was dispatched to execution
    POLICY_DENIED = "POLICY_DENIED"                  # Policy Enforcement Point denied request
    ACCESS_PERMITTED = "RESOURCE_ACCESS_PERMITTED"  # Alias for RESOURCE_ACCESS_PERMITTED
    ACCESS_BLOCKED = "RESOURCE_ACCESS_DENIED"        # Alias for RESOURCE_ACCESS_DENIED
    DATA_EXFILTRATION_CONFIRMED = "CONFIRMED_BREACH" # Actual exfiltration breach
    QUARANTINE_VERIFIED = "RUNTIME_QUARANTINED"      # Alias for RUNTIME_QUARANTINED
    AUDIT_COMMITTED = "AUDIT_COMMITTED"              # Cryptographic SHA-256 ledger block committed
    SUCCESS_PERMITTED = "SUCCESS_PERMITTED"          # Benign action executed within allowed policy
    SUCCESS_PROHIBITED = "CONFIRMED_BREACH"          # Prohibited action succeeded (Security breach!)
    INCONCLUSIVE = "INCONCLUSIVE"                    # Available evidence is insufficient to establish outcome
    MALFORMED_REQUEST = "MALFORMED_REQUEST"          # Model output invalid schema


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
    model_layer_jailbreak: str = "FAILED"
    pep_defense: str = "NOT_APPLICABLE"
    confirmed_breach: str = "NO"

