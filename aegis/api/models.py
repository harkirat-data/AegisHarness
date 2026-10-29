"""
Data Models & Serialization Schemas for AegisHarness API
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackLaunchRequest(BaseModel):
    attack_id: Optional[str] = Field(None, description="Pre-configured attack ID from library")
    custom_prompt: Optional[str] = Field(None, description="Custom user-defined jailbreak prompt")
    custom_command: Optional[str] = Field(None, description="Custom target tool command to execute")
    session_id: Optional[str] = Field(None, description="Optional custom session ID")
    use_real_agent: bool = Field(True, description="Whether to route through real local LLM autonomous agent")
    target_model: Optional[str] = Field("qwen2.5:3b", description="Target model identifier")
    repeat_count: int = Field(1, ge=1, le=5, description="Number of repetitions to run")


class ManualQuarantineRequest(BaseModel):
    session_id: str
    reason: Optional[str] = "Manual operator kill switch triggered from dashboard"


class ManualQuarantineResponse(BaseModel):
    success: bool = True
    verified: bool = True
    status: str
    sandbox_id: str
    session_id: str
    workload_pid: Optional[int] = None
    process_terminated: bool = True
    memory_wiped: bool = True
    latency_ms: Optional[float] = None
    slaughter_latency_ms: Optional[float] = None
    audit_record_index: Optional[int] = None
    audit_hash: Optional[str] = None
    reason: str


class DiagnosticTraceStage(BaseModel):
    stage: str
    timestamp: str
    description: str
    evidence: Dict[str, Any]


class AttackExecutionResponse(BaseModel):
    test_run_id: str
    session_id: str
    sandbox_id: str
    workload_pid: Optional[int] = None
    workload_alive_before: bool = True
    workload_alive_after: bool = False
    attack_id: str
    outcome_type: str = "INCONCLUSIVE"
    trapped: bool
    syscall_intercepted: Optional[str]
    quarantined: bool
    quarantine_latency_ms: float
    output: str
    last_audit_hash: str
    audit_block_index: Optional[int] = None
    status: str
    use_real_agent: bool = True
    model_name: Optional[str] = None
    model_refusal: bool = False
    latency_breakdown: Optional[Dict[str, float]] = None
    trace_stages: List[Dict[str, Any]] = []


class LedgerVerifyResponse(BaseModel):
    is_valid: bool
    message: str
    block_count: int
    tip_hash: Optional[str]
    compromised_index: Optional[int] = None


class SystemStatusResponse(BaseModel):
    status: str
    version: str
    active_sandboxes: int
    total_ledger_records: int
    zero_trust_egress: bool
    read_only_weights: bool
    ledger_integrity_valid: bool
    llm_provider: str = "ollama"
    model_name: str = "qwen2.5:3b"
    model_online: bool = False
    gpu_hardware: str = "NVIDIA GeForce RTX 3050 Laptop GPU (4GB VRAM)"
    isolation_mode: str = "Tri-Workload Ephemeral Synthetic VFS & OS Process Isolation"


class ModelCompareRequest(BaseModel):
    models: List[str] = Field(["qwen2.5:3b", "gemma2:2b"], description="List of target models to evaluate")
    prompt: Optional[str] = Field(None, description="Custom prompt to test across models")
    attack_id: Optional[str] = Field(None, description="Attack template ID from library")
    test_objective: Optional[str] = Field(None, description="Security evaluation objective")
    scope: str = Field("General", description="Authorized resource scope")


class ModelEvaluationResult(BaseModel):
    model_name: str
    installed: bool = True
    install_command: Optional[str] = None
    raw_response: str = ""
    model_refused: bool = False
    proposed_tool: Optional[Dict[str, Any]] = None
    pep_authorized: bool = False
    outcome_type: str = "INCONCLUSIVE"
    test_verdict: str = "PENDING"
    verdict_explanation: str = ""
    latency_ms: float = 0.0
    evidence_recorded: bool = True


class ModelCompareResponse(BaseModel):
    comparison_id: str
    evaluated_prompt: str
    models_evaluated: int
    results: List[ModelEvaluationResult]
    security_control_independence_note: str


class VoiceBriefingRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional specific session ID to summarize")
    include_audio: bool = Field(True, description="Whether to generate MP3 speech via ElevenLabs")


class VoiceBriefingResponse(BaseModel):
    session_id: str
    briefing_text: str
    audio_base64: Optional[str] = None
    audio_available: bool = False
    voice_provider: str = "ElevenLabs"
    notice: str


class VoiceQueryRequest(BaseModel):
    query: str = Field(..., description="Operator query about incidents, ledger, or containment")
    include_audio: bool = Field(True, description="Whether to synthesize speech for the answer")


class VoiceQueryResponse(BaseModel):
    query: str
    answer_text: str
    audio_base64: Optional[str] = None
    audio_available: bool = False
    grounded_in_ledger: bool = True
    events_inspected: int = 0


class ChatMessage(BaseModel):
    role: str
    content: str
    timestamp: Optional[str] = None
    sources: List[str] = []
    scope_status: Optional[str] = None


class ChatRequest(BaseModel):
    message: str = Field(..., description="User prompt or question to the agent")
    session_id: Optional[str] = Field(None, description="Active conversation session ID")
    execution_id: Optional[str] = Field(None, description="Optional unique execution ID for request correlation")
    target_model: Optional[str] = Field(None, description="Target model identifier")
    assistant_mode: str = Field("company", description="'company' or 'general'")
    history: List[ChatMessage] = Field(default_factory=list, description="Recent conversation turns")


class ChatResponse(BaseModel):
    session_id: str
    execution_id: str = ""
    timestamp: str = ""
    message: str
    final_response: str = ""
    raw_response: str = ""
    target_model: str
    model_name: Optional[str] = None
    assistant_mode: str
    scope_status: str = "IN_SCOPE"
    sources: List[str] = []
    tool_proposal: Optional[Dict[str, Any]] = None
    tool_executed: Optional[str] = None
    tool_name: Optional[str] = None
    tool_status: Optional[str] = None
    tool_output_preview: Optional[str] = None
    model_decision: str = "NOT EXECUTED"
    pep_decision: str = "NOT EXECUTED"
    tool_invocation: str = "NOT EXECUTED"
    resource_access_outcome: str = "NOT EXECUTED"
    runtime_containment: str = "NOT EXECUTED"
    audit_persistence: str = "NOT EXECUTED"
    runtime_isolation_claim: str = "NONE_VERIFIED"
    policy_decision: Optional[str] = None
    pep_authorized: Optional[bool] = None
    pep_reason: str = ""
    outcome_type: str = "SUCCESS_PERMITTED"
    audit_hash: Optional[str] = None
    audit_event_id: Optional[str] = None
    audit_block_index: Optional[int] = None
    latency_ms: float = 0.0
    trace_stages: List[Dict[str, Any]] = []


class DirectPEPTestRequest(BaseModel):
    tool: Optional[str] = Field(None, description="Tool name to evaluate directly against PEP")
    tool_name: Optional[str] = Field(None, description="Alternative key for tool name")
    arguments: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Tool arguments dictionary")
    argument: Optional[str] = Field(None, description="String argument for single-argument tools")
    session_id: Optional[str] = Field(None, description="Optional session ID")
    execution_id: Optional[str] = Field(None, description="Optional execution ID")
    test_run_id: Optional[str] = Field(None, description="Optional test run ID")
    security_objective: Optional[str] = Field("Direct PEP Authorization Verification", description="Security objective")
    assistant_mode: str = Field("company", description="Identity mode: 'company' or 'general'")


class DirectPEPTestResponse(BaseModel):
    execution_id: str
    session_id: str
    test_run_id: str
    tool: str
    tool_name: str = ""
    arguments: Dict[str, Any] = Field(default_factory=dict)
    tool_arguments: Dict[str, Any] = Field(default_factory=dict)
    security_objective: str
    assistant_mode: str
    pep_decision: str
    pep_authorized: bool = False
    resource_access_outcome: str = "ACCESS_DENIED"
    policy_reason: str = ""
    status: str
    outcome_type: str
    output_preview: str
    security_event_triggered: bool
    runtime_containment: str
    audit_hash: Optional[str] = None
    audit_block_index: Optional[int] = None
    audit_persistence: str = "COMMITTED"
    isolation_claim: str = "APPLICATION_LEVEL_PEP"
    latency_ms: float = 0.0
    trace_stages: List[Dict[str, Any]] = Field(default_factory=list)

