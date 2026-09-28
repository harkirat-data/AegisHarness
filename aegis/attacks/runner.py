"""
Red-Team Automated Attack Runner (Red Zone)
Dispatches adversarial exploits and benign baseline tasks to evaluate sandbox resilience.
Calculates defense metrics and test suite scorecards.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.attacks.library import ATTACK_LIBRARY, AttackPayload
from aegis.core.audit_ledger import TamperProofAuditLedger


@dataclass
class AttackExecutionResult:
    attack_id: str
    attack_name: str
    category: str
    is_adversarial: bool
    prompt: str
    command: str
    trapped_by_sandbox: bool
    syscall_intercepted: Optional[str]
    quarantined: bool
    quarantine_latency_ms: float
    audit_hash: str
    execution_time_ms: float
    details: Dict[str, Any]


class RedTeamRunner:
    """
    Simulates automated red-teaming toolchains (e.g., Garak/PyRIT) delivering payloads
    over the strict API ingress pipe into the Target Zone.
    """

    def __init__(self, orchestrator: Any, ledger: Optional[TamperProofAuditLedger] = None):
        self.orchestrator = orchestrator
        self.ledger = ledger
        self.history: List[AttackExecutionResult] = []

    def execute_payload(self, attack: AttackPayload, session_id: Optional[str] = None) -> AttackExecutionResult:
        start_time = time.perf_counter()
        session_id = session_id or f"sess-red-{int(time.time()*1000)}"

        # Blue-Team Ledger records Red-Zone attack dispatch
        if self.ledger:
            self.ledger.append_event(
                session_id=session_id,
                source_zone="RED",
                event_type="ATTACK_DISPATCHED",
                severity=attack.severity_level,
                details={
                    "attack_id": attack.id,
                    "attack_name": attack.name,
                    "category": attack.category,
                    "prompt": attack.prompt[:120],
                    "target_tool_command": attack.target_tool_command,
                    "mitre_tag": attack.mitre_atlas_tag,
                },
            )

        # Dispatch through the Orchestrator
        orch_result = self.orchestrator.process_ingress_payload(
            session_id=session_id,
            attack=attack,
        )

        total_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        result = AttackExecutionResult(
            attack_id=attack.id,
            attack_name=attack.name,
            category=attack.category,
            is_adversarial=attack.is_adversarial,
            prompt=attack.prompt,
            command=attack.target_tool_command,
            trapped_by_sandbox=orch_result.get("trapped", False),
            syscall_intercepted=orch_result.get("syscall_intercepted"),
            quarantined=orch_result.get("quarantined", False),
            quarantine_latency_ms=orch_result.get("quarantine_latency_ms", 0.0),
            audit_hash=orch_result.get("last_audit_hash", ""),
            execution_time_ms=total_time_ms,
            details=orch_result,
        )

        self.history.append(result)
        return result

    def run_full_suite(self) -> Dict[str, Any]:
        """Runs the entire battery of adversarial exploits and benign controls."""
        results = []
        for attack in ATTACK_LIBRARY.values():
            res = self.execute_payload(attack)
            results.append(res)

        total = len(results)
        adversarial_tests = [r for r in results if r.is_adversarial]
        trapped_count = sum(1 for r in adversarial_tests if r.trapped_by_sandbox)
        interception_rate = round((trapped_count / len(adversarial_tests) * 100), 1) if adversarial_tests else 100.0

        avg_latency = (
            round(sum(r.quarantine_latency_ms for r in adversarial_tests if r.quarantined) / len(adversarial_tests), 2)
            if adversarial_tests
            else 0.0
        )

        return {
            "total_tests": total,
            "adversarial_tests": len(adversarial_tests),
            "threats_trapped": trapped_count,
            "interception_success_rate_percent": interception_rate,
            "average_quarantine_latency_ms": avg_latency,
            "test_summary": [
                {
                    "id": r.attack_id,
                    "name": r.attack_name,
                    "trapped": r.trapped_by_sandbox,
                    "quarantined": r.quarantined,
                    "latency_ms": r.quarantine_latency_ms,
                }
                for r in results
            ],
        }
