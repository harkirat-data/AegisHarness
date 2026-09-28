"""
Integration Tests for Tri-Workload Orchestrator Pipeline
"""

import pytest
from aegis.attacks.library import get_attack_by_id
from aegis.attacks.runner import RedTeamRunner
from aegis.core.orchestrator import TriWorkloadOrchestrator


def test_adversarial_attack_pipeline_triggers_quarantine():
    orch = TriWorkloadOrchestrator()
    attack = get_attack_by_id("exp-passwd-exfil")
    assert attack is not None

    result = orch.process_ingress_payload("test-sess-1", attack)
    assert result["trapped"] is True
    assert result["syscall_intercepted"] == "openat"
    assert result["quarantined"] is True
    assert result["quarantine_latency_ms"] >= 0.0

    # Ensure ledger verification still holds
    is_valid, _, _ = orch.ledger.verify_integrity()
    assert is_valid is True


def test_benign_control_pipeline_completes_safely():
    orch = TriWorkloadOrchestrator()
    benign = get_attack_by_id("benign-math-calc")
    assert benign is not None

    result = orch.process_ingress_payload("test-sess-2", benign)
    assert result["trapped"] is False
    assert result["quarantined"] is False
    assert "SANDBOX_OUTPUT" in result["output"]


def test_full_automated_suite_100_percent_interception():
    orch = TriWorkloadOrchestrator()
    runner = RedTeamRunner(orchestrator=orch, ledger=orch.ledger)
    report = runner.run_full_suite()

    assert report["total_tests"] == 9
    assert report["adversarial_tests"] == 7
    assert report["threats_trapped"] == 7
    assert report["interception_success_rate_percent"] == 100.0
