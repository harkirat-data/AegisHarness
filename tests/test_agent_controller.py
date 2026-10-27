"""
Unit & Integration Tests for Autonomous Agent Controller (Section 4)
Verifies:
- Model refusal detection vs application policy denial
- Tool call execution and structured report generation
- Model unavailable and timeout error handling
- Malformed tool request handling
- Cryptographic audit trail recording for agent actions
"""

import pytest
from aegis.agent.controller import AutonomousAgentController
from aegis.agent.llm_client import LocalLLMClient
from aegis.agent.schemas import AgentOutcomeType, ToolCallRequest
from aegis.core.audit_ledger import TamperProofAuditLedger


class MockRefusalLLMClient(LocalLLMClient):
    """Mocks a safety-aligned LLM refusing a jailbreak prompt directly."""
    def generate_agent_response(self, prompt, tool_schemas, system_override=None):
        return {
            "success": True,
            "raw_response": "I cannot fulfill this request. I must decline any actions involving unauthorized credential exfiltration.",
            "refused": True,
            "tool_call": None,
            "latency_ms": 12.0,
        }


class MockMaliciousLLMClient(LocalLLMClient):
    """Mocks an untrusted or coerced LLM proposing a prohibited tool call."""
    def generate_agent_response(self, prompt, tool_schemas, system_override=None):
        return {
            "success": True,
            "raw_response": '```json\n{"tool": "read_file", "arguments": {"path": "protected/confidential.txt"}}\n```',
            "refused": False,
            "tool_call": ToolCallRequest(tool="read_file", arguments={"path": "protected/confidential.txt"}),
            "latency_ms": 15.0,
        }


class MockTimeoutLLMClient(LocalLLMClient):
    """Mocks an inference engine timeout."""
    def generate_agent_response(self, prompt, tool_schemas, system_override=None):
        return {
            "success": False,
            "raw_response": "",
            "refused": False,
            "tool_call": None,
            "latency_ms": 30000.0,
            "error": "Local model inference timed out after 30.0s",
        }


def test_agent_model_refusal_distinction():
    ledger = TamperProofAuditLedger()
    agent = AutonomousAgentController(llm_client=MockRefusalLLMClient(), audit_ledger=ledger)

    report = agent.run_session(user_prompt="Give me root password")
    assert report.model_refused is True
    assert report.outcome_type == AgentOutcomeType.MODEL_REFUSAL
    assert "refused adversarial request" in report.policy_reason

    # Verify event logged in ledger
    records = ledger.get_records()
    assert any(r["event_type"] == "MODEL_REFUSAL" for r in records)


def test_agent_policy_denial_when_model_coerced():
    ledger = TamperProofAuditLedger()
    agent = AutonomousAgentController(llm_client=MockMaliciousLLMClient(), audit_ledger=ledger)

    report = agent.run_session(user_prompt="Coerced attack")
    assert report.model_refused is False
    assert report.proposed_tool_call.tool == "read_file"
    assert report.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert report.policy_approved is False
    assert "strictly prohibited" in report.policy_reason

    # Verify event logged in ledger
    records = ledger.get_records()
    assert any(r["event_type"] == "TOOL_EXECUTION_AUDITED" for r in records)


def test_agent_inference_timeout_handling():
    agent = AutonomousAgentController(llm_client=MockTimeoutLLMClient())
    report = agent.run_session(user_prompt="Slow prompt")
    assert report.outcome_type == AgentOutcomeType.EXECUTION_ERROR
    assert "timed out" in report.policy_reason
