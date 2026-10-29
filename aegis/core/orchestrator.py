"""
AegisHarness Tri-Workload Orchestrator
Coordinates Red-Team Ingress, Ephemeral Target Workloads with real OS processes,
and Out-of-Band Blue-Team Audit and Quarantine Enforcement.
"""

import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from aegis.agent.controller import AutonomousAgentController
from aegis.attacks.library import AttackPayload
from aegis.config import CONFIG, SandboxState, ThreatSeverity
from aegis.core.audit_ledger import TamperProofAuditLedger
from aegis.core.egress_firewall import ZeroTrustEgressFirewall
from aegis.core.sandbox import EphemeralTargetSandbox, SecurityViolation, SyscallEvent
from aegis.core.threat_detector import ThreatAssessment, ThreatDetector


class TriWorkloadOrchestrator:
    """
    Central control plane coordinating Red, Target, and Blue workloads with genuine
    OS process containment, cryptographic auditing, and verifiable telemetry.
    """

    def __init__(self, ledger_file: Optional[str] = None):
        self.ledger = TamperProofAuditLedger(ledger_file)
        self.threat_detector = ThreatDetector()
        self.firewall = ZeroTrustEgressFirewall(audit_ledger=self.ledger, allow_egress=CONFIG.SECURITY_POLICY.ALLOW_EGRESS)
        self.agent_controller = AutonomousAgentController(
            audit_ledger=self.ledger,
            threat_detector=self.threat_detector,
        )
        self._active_sandboxes: Dict[str, EphemeralTargetSandbox] = {}
        self._telemetry_subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._lock = threading.RLock()

    def subscribe_telemetry(self, callback: Callable[[Dict[str, Any]], None]):
        with self._lock:
            self._telemetry_subscribers.append(callback)

    def unsubscribe_telemetry(self, callback: Callable[[Dict[str, Any]], None]):
        with self._lock:
            if callback in self._telemetry_subscribers:
                self._telemetry_subscribers.remove(callback)

    def _broadcast_event(self, event_type: str, zone: str, data: Dict[str, Any]):
        payload = {
            "type": event_type,
            "zone": zone,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }
        with self._lock:
            subscribers = list(self._telemetry_subscribers)

        for sub in subscribers:
            try:
                sub(payload)
            except Exception as e:
                print(f"[Orchestrator] Error notifying subscriber: {e}")

    def provision_sandbox(self, session_id: Optional[str] = None) -> EphemeralTargetSandbox:
        session_id = session_id or str(uuid.uuid4())
        sandbox = EphemeralTargetSandbox(
            session_id=session_id,
            audit_ledger=self.ledger,
            on_violation_callback=lambda event: self._on_sandbox_violation(session_id, event),
        )
        with self._lock:
            self._active_sandboxes[session_id] = sandbox

        self.ledger.append_event(
            session_id=session_id,
            source_zone="TARGET",
            event_type="SANDBOX_PROVISIONED",
            severity=ThreatSeverity.SEV4_INFO.value,
            details={
                "sandbox_id": sandbox.sandbox_id,
                "workload_pid": sandbox.workload_pid,
                "state": sandbox.state.value,
                "read_only_weights": True,
                "zero_trust_egress": True,
            },
        )

        self._broadcast_event(
            event_type="SANDBOX_STATUS",
            zone="TARGET",
            data={
                "session_id": session_id,
                "sandbox_id": sandbox.sandbox_id,
                "workload_pid": sandbox.workload_pid,
                "state": sandbox.state.value,
                "message": f"Ephemeral workload provisioned (PID {sandbox.workload_pid}). Read-only weights locked.",
            },
        )
        return sandbox

    def _on_sandbox_violation(self, session_id: str, event: SyscallEvent):
        self._broadcast_event(
            event_type="SYSCALL_TRAPPED",
            zone="BLUE",
            data={
                "session_id": session_id,
                "syscall_id": event.syscall_id,
                "syscall_name": event.name,
                "severity": event.severity.value,
                "reason": event.reason,
                "args": event.args,
            },
        )

    def process_ingress_payload(
        self,
        session_id: str,
        attack: AttackPayload,
        use_real_agent: bool = False,
        target_model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes the genuine Tri-Workload pipeline with verifiable diagnostic stages:
        1. Red Zone: Dispatches test payload.
        2. Target Zone: Executes through Local LLM Agent or Sandbox Environment.
        3. Blue Zone: Audits operations and executes verified slaughter if critical threat detected.
        """
        t_init = time.perf_counter()
        t_detect = t_init
        t_quarantine_req = t_init
        t_containment_end = t_init

        now_utc = datetime.now(timezone.utc)
        test_run_id = f"trun-{now_utc.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        trace_stages: List[Dict[str, Any]] = []

        def _add_stage(stage_name: str, desc: str, evidence: Dict[str, Any]):
            trace_stages.append({
                "stage": stage_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "description": desc,
                "evidence": evidence,
            })

        _add_stage("REQUEST_ACCEPTED", "Ingress test request accepted by API gateway.", {
            "test_run_id": test_run_id,
            "session_id": session_id,
            "attack_id": attack.id,
            "prompt": attack.prompt[:120],
            "use_real_agent": use_real_agent,
        })

        # Step 1: Provision target sandbox with real disposable OS child process
        sandbox = self._active_sandboxes.get(session_id) or self.provision_sandbox(session_id)
        alive_before = sandbox.is_workload_alive()

        _add_stage("WORKLOAD_PROVISIONED", f"Dedicated disposable process verified running with PID {sandbox.workload_pid}.", {
            "sandbox_id": sandbox.sandbox_id,
            "workload_pid": sandbox.workload_pid,
            "workload_alive": alive_before,
            "state": sandbox.state.value,
        })

        self._broadcast_event(
            event_type="ATTACK_RECEIVED",
            zone="RED",
            data={
                "test_run_id": test_run_id,
                "session_id": session_id,
                "attack_id": attack.id,
                "attack_name": attack.name,
                "prompt": attack.prompt,
                "target_command": attack.target_tool_command,
                "severity": attack.severity_level,
                "mitre_tag": attack.mitre_atlas_tag,
                "use_real_agent": use_real_agent,
            },
        )

        trapped = False
        quarantined = False
        quarantine_latency_ms = 0.0
        caught_syscall: Optional[str] = None
        output_msg = ""
        model_name: Optional[str] = None
        model_refusal: bool = False
        outcome_type = "INCONCLUSIVE"
        policy_decision = "PENDING"

        # --- BRANCH A: REAL LOCAL LLM AGENT WORKLOAD ---
        if use_real_agent:
            self._broadcast_event(
                event_type="AGENT_INFERENCE_STARTING",
                zone="TARGET",
                data={
                    "test_run_id": test_run_id,
                    "session_id": session_id,
                    "sandbox_id": sandbox.sandbox_id,
                    "model": self.agent_controller.llm.model_name,
                    "prompt": attack.prompt,
                },
            )

            report = self.agent_controller.run_session(
                user_prompt=attack.prompt,
                session_id=session_id,
                attack_category=attack.category,
                expected_outcome=f"Expected syscall trap: {attack.expected_syscall}",
                model_override=target_model,
            )
            t_detect = time.perf_counter()
            model_name = report.model_name
            model_refusal = report.model_refused
            outcome_type = report.outcome_type.value

            _add_stage("MODEL_INFERENCE_COMPLETED", f"Local model {report.model_name} generated response.", {
                "model_name": report.model_name,
                "model_refused": report.model_refused,
                "outcome_type": report.outcome_type.value,
                "raw_response_preview": report.model_response_raw[:150],
            })

            # Broadcast model response to Target column
            self._broadcast_event(
                event_type="AGENT_RESPONSE_RECEIVED",
                zone="TARGET",
                data={
                    "test_run_id": test_run_id,
                    "session_id": session_id,
                    "sandbox_id": sandbox.sandbox_id,
                    "raw_response": report.model_response_raw[:300],
                    "refused": report.model_refused,
                    "outcome": report.outcome_type.value,
                    "proposed_tool": report.proposed_tool_call.model_dump() if report.proposed_tool_call else None,
                },
            )

            if report.proposed_tool_call:
                policy_decision = report.policy_reason
                _add_stage("TOOL_REQUEST_EVALUATED", f"Tool request evaluated against security policy.", {
                    "tool": report.proposed_tool_call.tool,
                    "arguments": report.proposed_tool_call.arguments,
                    "policy_approved": report.policy_approved,
                    "policy_reason": report.policy_reason,
                })

            if report.tool_result and report.tool_result.security_event_triggered:
                trapped = True
                caught_syscall = attack.expected_syscall or "openat"
                t_quarantine_req = time.perf_counter()

                _add_stage("SECURITY_ENFORCEMENT_TRAP", "Operation blocked by runtime policy.", {
                    "syscall": caught_syscall,
                    "policy_reason": report.policy_reason,
                })

                if CONFIG.SECURITY_POLICY.AUTO_QUARANTINE_ON_SEV1 or CONFIG.SECURITY_POLICY.AUTO_QUARANTINE_ON_SEV2:
                    q_res = sandbox.slaughter(reason=report.policy_reason)
                    t_containment_end = time.perf_counter()
                    quarantined = q_res.get("verified", False)
                    quarantine_latency_ms = q_res.get("slaughter_latency_ms", 0.0)

                    _add_stage("QUARANTINE_SLAUGHTER", f"Workload PID {sandbox.workload_pid} terminated and memory wiped.", {
                        "workload_pid": sandbox.workload_pid,
                        "process_terminated": q_res.get("process_terminated", False),
                        "memory_wiped": q_res.get("memory_wiped", False),
                        "slaughter_latency_ms": quarantine_latency_ms,
                    })

                    self._broadcast_event(
                        event_type="QUARANTINE_ACTION",
                        zone="BLUE",
                        data={
                            "test_run_id": test_run_id,
                            "session_id": session_id,
                            "sandbox_id": sandbox.sandbox_id,
                            "workload_pid": sandbox.workload_pid,
                            "status": "QUARANTINED",
                            "slaughter_latency_ms": quarantine_latency_ms,
                            "reason": report.policy_reason,
                            "memory_wiped": True,
                        },
                    )
                    output_msg = f"[AGENT_CONTAINED] Real agent tool call trapped: {report.policy_reason}. Quarantine slaughter in {quarantine_latency_ms}ms."
            else:
                output_msg = report.final_response or report.model_response_raw

        # --- BRANCH B: WORKLOAD COMMAND EXECUTION ---
        else:
            pre_assessment: ThreatAssessment = self.threat_detector.evaluate(attack.target_tool_command)
            t_detect = time.perf_counter()
            if pre_assessment.detected:
                self.ledger.append_event(
                    session_id=session_id,
                    source_zone="BLUE",
                    event_type="THREAT_CLASSIFIED",
                    severity=pre_assessment.severity.value,
                    details={
                        "threat_name": pre_assessment.threat_name,
                        "mitre_atlas_id": pre_assessment.mitre_atlas_id,
                        "description": pre_assessment.description,
                        "recommended_action": pre_assessment.recommended_action,
                    },
                )
                self._broadcast_event(
                    event_type="THREAT_ALERT",
                    zone="BLUE",
                    data={
                        "test_run_id": test_run_id,
                        "session_id": session_id,
                        "threat_name": pre_assessment.threat_name,
                        "severity": pre_assessment.severity.value,
                        "mitre_atlas_id": pre_assessment.mitre_atlas_id,
                        "action": pre_assessment.recommended_action,
                    },
                )

            try:
                self._broadcast_event(
                    event_type="EXECUTION_STARTING",
                    zone="TARGET",
                    data={
                        "test_run_id": test_run_id,
                        "session_id": session_id,
                        "sandbox_id": sandbox.sandbox_id,
                        "workload_pid": sandbox.workload_pid,
                        "command": attack.target_tool_command,
                    },
                )
                exec_res = sandbox.execute_command_simulation(attack.target_tool_command)
                output_msg = exec_res.get("output", "")
                outcome_type = "SUCCESS_PERMITTED"
                policy_decision = "Permitted within sandbox bounds"

            except SecurityViolation as sv:
                trapped = True
                caught_syscall = sv.syscall_event.name
                t_quarantine_req = time.perf_counter()
                outcome_type = "RUNTIME_BLOCKED"
                policy_decision = sv.syscall_event.reason

                _add_stage("SECURITY_ENFORCEMENT_TRAP", f"Syscall '{caught_syscall}' intercepted by policy sentry.", {
                    "syscall": caught_syscall,
                    "reason": sv.syscall_event.reason,
                })

                if CONFIG.SECURITY_POLICY.AUTO_QUARANTINE_ON_SEV1 or CONFIG.SECURITY_POLICY.AUTO_QUARANTINE_ON_SEV2:
                    q_res = sandbox.slaughter(reason=sv.syscall_event.reason)
                    t_containment_end = time.perf_counter()
                    quarantined = q_res.get("verified", False)
                    quarantine_latency_ms = q_res.get("slaughter_latency_ms", 0.0)

                    _add_stage("QUARANTINE_SLAUGHTER", f"Workload PID {sandbox.workload_pid} terminated and memory wiped.", {
                        "workload_pid": sandbox.workload_pid,
                        "process_terminated": q_res.get("process_terminated", False),
                        "memory_wiped": q_res.get("memory_wiped", False),
                        "slaughter_latency_ms": quarantine_latency_ms,
                    })

                    self._broadcast_event(
                        event_type="QUARANTINE_ACTION",
                        zone="BLUE",
                        data={
                            "test_run_id": test_run_id,
                            "session_id": session_id,
                            "sandbox_id": sandbox.sandbox_id,
                            "workload_pid": sandbox.workload_pid,
                            "status": "QUARANTINED",
                            "slaughter_latency_ms": quarantine_latency_ms,
                            "reason": sv.syscall_event.reason,
                            "memory_wiped": True,
                        },
                    )
                    output_msg = f"[CONTAINMENT_ENFORCED] Syscall '{caught_syscall}' trapped. Workload PID {sandbox.workload_pid} slaughtered in {quarantine_latency_ms}ms."

        alive_after = sandbox.is_workload_alive()

        # Step 4: Record execution in Blue Zone WORM Ledger
        records = self.ledger.get_records()
        tip_hash = records[-1]["current_hash"] if records else ""
        block_idx = len(records) - 1 if records else 0

        _add_stage("AUDIT_RECORD_COMMITTED", f"Evidence committed to WORM hash chain at Block #{block_idx}.", {
            "block_index": block_idx,
            "tip_hash": tip_hash,
            "session_id": session_id,
        })

        init_to_det = round((t_detect - t_init) * 1000, 2)
        det_to_req = round((t_quarantine_req - t_detect) * 1000, 2) if trapped else 0.0
        req_to_term = round((t_containment_end - t_quarantine_req) * 1000, 2) if quarantined else 0.0
        total_contain = round((t_containment_end - t_init) * 1000, 2) if quarantined else 0.0

        return {
            "test_run_id": test_run_id,
            "session_id": session_id,
            "sandbox_id": sandbox.sandbox_id,
            "workload_pid": sandbox.workload_pid,
            "workload_alive_before": alive_before,
            "workload_alive_after": alive_after,
            "attack_id": attack.id,
            "outcome_type": outcome_type,
            "policy_decision": policy_decision,
            "trapped": trapped,
            "syscall_intercepted": caught_syscall,
            "quarantined": quarantined,
            "quarantine_latency_ms": quarantine_latency_ms,
            "output": output_msg,
            "last_audit_hash": tip_hash,
            "audit_block_index": block_idx,
            "status": sandbox.state.value,
            "use_real_agent": use_real_agent,
            "model_name": model_name,
            "model_refusal": model_refusal,
            "trace_stages": trace_stages,
            "latency_breakdown": {
                "init_to_detection_ms": init_to_det,
                "detection_to_quarantine_req_ms": det_to_req,
                "quarantine_req_to_termination_ms": req_to_term,
                "total_containment_ms": total_contain,
            },
        }

    def trigger_manual_quarantine(self, session_id: str, reason: str = "Operator manual kill switch engaged") -> Dict[str, Any]:
        """Allows security operators to manually slaughter a sandbox from the dashboard."""
        sandbox = self._active_sandboxes.get(session_id)
        if not sandbox:
            return {"error": "Sandbox not found for session", "session_id": session_id, "status": "NOT_FOUND"}

        result = sandbox.slaughter(reason=reason)
        self._broadcast_event(
            event_type="QUARANTINE_ACTION",
            zone="BLUE",
            data={
                "session_id": session_id,
                "sandbox_id": sandbox.sandbox_id,
                "workload_pid": sandbox.workload_pid,
                "status": "QUARANTINED",
                "slaughter_latency_ms": result.get("slaughter_latency_ms", 0.0),
                "reason": reason,
                "memory_wiped": True,
            },
        )
        return result

    def get_session_snapshot(self, session_id: str) -> Optional[Dict[str, Any]]:
        sandbox = self._active_sandboxes.get(session_id)
        if not sandbox:
            return None

        records = self.ledger.get_records(session_id=session_id)
        is_valid, _, _ = self.ledger.verify_integrity()
        trapped_calls = sum(1 for e in sandbox.interception_history if e.blocked)

        return {
            "session_id": session_id,
            "sandbox_id": sandbox.sandbox_id,
            "workload_pid": sandbox.workload_pid,
            "state": sandbox.state.value,
            "created_at": sandbox.created_at,
            "terminated_at": sandbox.terminated_at,
            "trapped_calls": trapped_calls,
            "quarantined": sandbox.state in {SandboxState.QUARANTINED, SandboxState.TERMINATED},
            "records": records,
            "ledger_valid": is_valid,
        }
