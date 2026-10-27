"""
AegisHarness Agent Controller
Orchestrates autonomous tool-calling workflow with strict zero-trust boundary verification.
"""

import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from aegis.agent.llm_client import LocalLLMClient
from aegis.agent.schemas import (
    AgentExecutionReport,
    AgentOutcomeType,
    ToolCallRequest,
    ToolResult,
)
from aegis.agent.tools import ControlledToolRegistry
from aegis.config import ThreatSeverity
from aegis.core.audit_ledger import TamperProofAuditLedger
from aegis.core.threat_detector import ThreatAssessment, ThreatDetector


class AutonomousAgentController:
    """Central controller managing agent actions, tool policy checks, audit logging, and quarantine."""

    def __init__(
        self,
        llm_client: Optional[LocalLLMClient] = None,
        tool_registry: Optional[ControlledToolRegistry] = None,
        audit_ledger: Optional[TamperProofAuditLedger] = None,
        threat_detector: Optional[ThreatDetector] = None,
        on_quarantine_callback: Optional[Callable[[str, str, float], None]] = None,
        max_iterations: int = 3,
    ):
        self.llm = llm_client or LocalLLMClient()
        self.tools = tool_registry or ControlledToolRegistry()
        self.ledger = audit_ledger
        self.threat_detector = threat_detector or ThreatDetector()
        self.on_quarantine = on_quarantine_callback
        self.max_iterations = max_iterations

    def _log(self, sid: str, zone: str, event: str, sev: str, details: Dict[str, Any]):
        return self.ledger.append_event(sid, zone, event, sev, details) if self.ledger else None

    def _report(self, sid: str, prompt: str, raw: str, outcome: AgentOutcomeType, reason: str, model_refused: bool = False, **kwargs) -> AgentExecutionReport:
        return AgentExecutionReport(
            session_id=sid,
            user_prompt=prompt,
            model_name=self.llm.model_name,
            model_response_raw=raw,
            model_refused=model_refused,
            outcome_type=outcome,
            policy_reason=reason,
            iteration_count=1,
            **kwargs,
        )

    def run_session(
        self,
        user_prompt: str,
        session_id: Optional[str] = None,
        attack_category: str = "Unknown",
        expected_outcome: str = "",
    ) -> AgentExecutionReport:
        sid = session_id or f"agent-sess-{uuid.uuid4().hex[:8]}"
        self._log(sid, "RED", "PROMPT_INGRESS", ThreatSeverity.SEV4_INFO.value, {"prompt": user_prompt, "attack_category": attack_category, "expected_outcome": expected_outcome})

        llm_res = self.llm.generate_agent_response(prompt=user_prompt, tool_schemas=self.tools.list_schemas())
        if not llm_res.get("success", False):
            err = llm_res.get("error", "Unknown inference error")
            self._log(sid, "TARGET", "INFERENCE_ERROR", ThreatSeverity.SEV3_MEDIUM.value, {"error": err, "latency_ms": llm_res.get("latency_ms", 0.0)})
            return self._report(sid, user_prompt, err, AgentOutcomeType.EXECUTION_ERROR, err)

        raw, is_refusal, tool_call = llm_res.get("raw_response", ""), llm_res.get("refused", False), llm_res.get("tool_call")

        # Step 3: Model safety refusal vs direct response
        if is_refusal and not tool_call:
            self._log(sid, "TARGET", "MODEL_REFUSAL", ThreatSeverity.SEV4_INFO.value, {"model": self.llm.model_name, "raw_response": raw[:300], "inference_latency_ms": llm_res.get("latency_ms", 0.0)})
            return self._report(sid, user_prompt, raw, AgentOutcomeType.MODEL_REFUSAL, "Model intrinsic safety guardrails refused adversarial request before tool execution.", model_refused=True)

        if not tool_call:
            self._log(sid, "TARGET", "DIRECT_RESPONSE", ThreatSeverity.SEV4_INFO.value, {"response": raw[:300]})
            return self._report(sid, user_prompt, raw, AgentOutcomeType.SUCCESS_PERMITTED, "Direct informational response generated with no tool execution required.", policy_approved=True)

        # Step 4: Independent Threat Classification & Tool Execution
        threat_eval: ThreatAssessment = self.threat_detector.evaluate(f"{tool_call.tool} {tool_call.arguments}")
        if threat_eval.detected:
            self._log(sid, "BLUE", "TOOL_THREAT_CLASSIFIED", threat_eval.severity.value, {"tool": tool_call.tool, "threat_name": threat_eval.threat_name, "mitre_atlas_id": threat_eval.mitre_atlas_id, "description": threat_eval.description})

        tool_result: ToolResult = self.tools.execute_tool(tool_call.tool, tool_call.arguments, session_id=sid)
        sev = tool_result.details.get("severity", ThreatSeverity.SEV1_CRITICAL.value) if tool_result.security_event_triggered else ThreatSeverity.SEV4_INFO.value

        rec = self._log(sid, "BLUE", "TOOL_EXECUTION_AUDITED", sev, {
            "tool": tool_result.tool, "status": tool_result.status, "outcome": tool_result.outcome_type.value,
            "execution_time_ms": tool_result.execution_time_ms, "security_event": tool_result.security_event_triggered,
            "output_preview": tool_result.output[:200], "details": tool_result.details,
        })
        audit_hash = rec.current_hash if rec else ""

        # Step 5: Automated Quarantine for Critical/High violations
        quarantined, q_latency = False, 0.0
        if tool_result.security_event_triggered and sev in {ThreatSeverity.SEV1_CRITICAL.value, ThreatSeverity.SEV2_HIGH.value}:
            quarantined = True
            q_start = time.perf_counter()
            if self.on_quarantine:
                self.on_quarantine(sid, tool_result.output, q_start)
            q_latency = round((time.perf_counter() - q_start) * 1000, 2)
            self._log(sid, "BLUE", "AGENT_WORKLOAD_QUARANTINED", ThreatSeverity.SEV1_CRITICAL.value, {"reason": tool_result.output, "triggering_tool": tool_result.tool, "quarantine_latency_ms": q_latency})

        return self._report(
            sid, user_prompt, raw, tool_result.outcome_type,
            tool_result.output if tool_result.status != "SUCCESS" else "Permitted by security policy.",
            proposed_tool_call=tool_call,
            policy_approved=(tool_result.status == "SUCCESS"),
            tool_result=tool_result,
            threat_severity=sev,
            quarantine_triggered=quarantined,
            quarantine_latency_ms=q_latency,
            audit_block_hash=audit_hash,
        )
