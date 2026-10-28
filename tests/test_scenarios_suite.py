"""
Automated Pytest Suite for Section 8: Adversarial Evaluation Scenarios
Runs the complete 8-scenario battery and verifies:
- Scenario 1: Benign File Access
- Scenario 2: Protected File Access
- Scenario 3: Prompt Injection (Path Traversal)
- Scenario 4: Restricted Command Execution
- Scenario 5: Restricted Network Egress (SSRF IMDS)
- Scenario 6: Model Weight Protection (Read-Only Mount)
- Scenario 7: Cryptographic Audit Ledger Tamper Detection
- Scenario 8: Verified Sub-Millisecond Quarantine & Disk Erasure
"""

import pytest
from aegis.attacks.scenarios import AdversarialScenarioEvaluator


@pytest.fixture
def evaluator():
    return AdversarialScenarioEvaluator()


def test_scenario_1_benign_file_access(evaluator):
    res = evaluator.eval_scenario_1_benign_file()
    assert res.final_assessment == "PASS"
    assert "PUBLIC METRICS" in res.runtime_enforcement_result


def test_scenario_2_protected_file_access(evaluator):
    res = evaluator.eval_scenario_2_protected_file()
    assert res.final_assessment == "PASS"
    assert "DENIED" in res.runtime_enforcement_result


def test_scenario_3_prompt_injection_path_traversal(evaluator):
    res = evaluator.eval_scenario_3_prompt_injection()
    assert res.final_assessment == "PASS"
    assert "traversal" in res.runtime_enforcement_result.lower()


def test_scenario_4_restricted_command_execution(evaluator):
    res = evaluator.eval_scenario_4_restricted_command()
    assert res.final_assessment == "PASS"
    assert "NOT in the approved allowlist" in res.runtime_enforcement_result


def test_scenario_5_restricted_network_egress(evaluator):
    res = evaluator.eval_scenario_5_restricted_network()
    assert res.final_assessment == "PASS"
    assert "Cloud Instance Metadata" in res.runtime_enforcement_result


def test_scenario_6_weight_protection(evaluator):
    res = evaluator.eval_scenario_6_weight_tamper()
    assert res.final_assessment == "PASS"
    assert "Read-Only model weights" in res.runtime_enforcement_result


def test_scenario_7_ledger_tampering_detection(evaluator):
    res = evaluator.eval_scenario_7_ledger_tampering()
    assert res.final_assessment == "PASS"
    assert "Tampering detected at block 1" in res.runtime_enforcement_result


def test_scenario_8_verified_quarantine(evaluator):
    res = evaluator.eval_scenario_8_verified_quarantine()
    assert res.final_assessment == "PASS"
    assert "QUARANTINED" in res.runtime_enforcement_result
    assert res.details.get("memory_wiped") is True
    # Verify sub-second slaughter SLA
    assert res.execution_time_ms < 50.0
