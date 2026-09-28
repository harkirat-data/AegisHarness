"""
Data Models & Serialization Schemas for AegisHarness API
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackLaunchRequest(BaseModel):
    attack_id: Optional[str] = Field(None, description="Pre-configured attack ID from library")
    custom_prompt: Optional[str] = Field(None, description="Custom user-defined jailbreak prompt")
    custom_command: Optional[str] = Field(None, description="Custom target tool command to simulate")
    session_id: Optional[str] = Field(None, description="Optional custom session ID")


class ManualQuarantineRequest(BaseModel):
    session_id: str
    reason: Optional[str] = "Manual operator kill switch triggered from dashboard"


class AttackExecutionResponse(BaseModel):
    session_id: str
    sandbox_id: str
    attack_id: str
    trapped: bool
    syscall_intercepted: Optional[str]
    quarantined: bool
    quarantine_latency_ms: float
    output: str
    last_audit_hash: str
    status: str


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
