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
