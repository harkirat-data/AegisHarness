"""
Tests for AegisHarness Chat-Based AI Workbench (Section 12 Test Matrix)
Verifies:
1. Normal chat request returns human-readable final response (no raw tool JSON).
2. Complete model-tool-response cycle with actual document retrieval.
3. Out-of-scope question handling in Company Assistant mode.
4. Gibberish input handling requesting clarification.
5. Model selection routing (qwen2.5:3b, gemma2:2b, llama3.2:3b).
6. Unsupported/unavailable model error handling.
7. PEP zero-trust policy denial for restricted resources in both modes.
8. WORM audit ledger recording of chat sessions.
9. Conversation history retrieval.
"""

import pytest
from starlette.testclient import TestClient
from aegis.api.server import app
from aegis.agent.controller import AutonomousAgentController
from aegis.agent.llm_client import LocalLLMClient
from aegis.agent.schemas import ToolCallRequest, AgentOutcomeType
from aegis.core.audit_ledger import TamperProofAuditLedger


client = TestClient(app)


class MockDocToolLLMClient(LocalLLMClient):
    """Mocks an LLM proposing a valid document retrieval, then summarizing the result."""
    def generate_agent_response(self, prompt, tool_schemas, system_override=None):
        return {
            "success": True,
            "raw_response": '```json\n{"tool": "read_document", "arguments": {"document_name": "information_security_policy.md"}}\n```',
            "refused": False,
            "tool_call": ToolCallRequest(tool="read_document", arguments={"document_name": "information_security_policy.md"}),
            "latency_ms": 15.0,
        }

    def generate_final_response(self, prompt: str, tool_name: str, tool_output: str, model_override=None):
        return "According to the Information Security Policy, all personnel must protect sensitive customer assets and follow access control procedures."


class MockRestrictedToolLLMClient(LocalLLMClient):
    """Mocks an LLM attempting to read confidential payroll files."""
    def generate_agent_response(self, prompt, tool_schemas, system_override=None):
        return {
            "success": True,
            "raw_response": '```json\n{"tool": "read_document", "arguments": {"document_name": "confidential_salaries.csv"}}\n```',
            "refused": False,
            "tool_call": ToolCallRequest(tool="read_document", arguments={"document_name": "confidential_salaries.csv"}),
            "latency_ms": 12.0,
        }

    def generate_final_response(self, prompt: str, tool_name: str, tool_output: str, model_override=None):
        return "I cannot access the confidential salaries document."


def test_1_and_2_normal_chat_returns_human_readable_final_response():
    """Points 1-5: Chat request executes tool, passes result to model, returns natural language answer (not raw tool JSON)."""
    controller = AutonomousAgentController(llm_client=MockDocToolLLMClient())
    report = controller.run_session(user_prompt="What does the security policy state?", assistant_mode="company")

    assert report.final_response != ""
    # Ensure final response is NOT the raw JSON tool proposal
    assert '{"tool": "read_document"' not in report.final_response
    assert "Information Security Policy" in report.final_response
    # Ensure sources correctly identify the retrieved document
    assert any("information_security_policy.md" in src for src in report.sources)
    assert report.policy_approved is True
    assert report.scope_status == "IN_SCOPE_COMPANY"


def test_6_inference_failure_honest_error():
    """Point 6: Model failure yields a truthful error status."""
    class FailingLLMClient(LocalLLMClient):
        def generate_agent_response(self, prompt, tool_schemas, system_override=None):
            return {"success": False, "raw_response": "", "refused": False, "tool_call": None, "latency_ms": 10.0, "error": "Connection refused to Ollama daemon"}

    controller = AutonomousAgentController(llm_client=FailingLLMClient())
    report = controller.run_session(user_prompt="Hello")
    assert report.outcome_type == AgentOutcomeType.EXECUTION_ERROR
    assert "Connection refused" in report.final_response or "unavailable" in report.final_response


def test_7_8_9_model_selection_routes_correctly():
    """Points 7-9: Qwen, Gemma, Llama selection preserves target_model."""
    models = ["qwen2.5:3b", "gemma2:2b", "llama3.2:3b"]
    for m in models:
        resp = client.post("/api/chat", json={
            "message": "What are our security protocols?",
            "target_model": m,
            "assistant_mode": "company"
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_model"] == m
        assert data["final_response"] != ""


def test_10_unavailable_model_returns_clear_error():
    """Point 10: Unavailable or unsupported model returns clear 400 error."""
    resp = client.post("/api/chat", json={
        "message": "Hello",
        "target_model": "non-existent-fake-model:99b",
        "assistant_mode": "company"
    })
    assert resp.status_code == 400
    assert "Unsupported model" in resp.json()["detail"]


def test_11_and_12_approved_vs_missing_document():
    """Points 11-12: Approved doc retrieves real contents; missing doc returns honest error."""
    from aegis.agent.tools import ControlledToolRegistry
    tools = ControlledToolRegistry()
    
    # Approved doc
    ok_res = tools.execute_tool("read_document", {"document_name": "information_security_policy.md"})
    assert ok_res.status == "SUCCESS"
    assert "INFORMATION SECURITY" in ok_res.output.upper()

    # Missing doc
    err_res = tools.execute_tool("read_document", {"document_name": "does_not_exist_file.txt"})
    assert err_res.status == "ERROR"
    assert "Document not found" in err_res.output


def test_13_out_of_scope_in_company_mode():
    """Point 13: General-knowledge question in Company Assistant mode is politely deferred."""
    controller = AutonomousAgentController()
    report = controller.run_session(user_prompt="Who is Virat Kohli?", assistant_mode="company")
    assert report.scope_status == "OUT_OF_SCOPE"
    assert "outside the configured scope of the Company Assistant" in report.final_response
    assert report.proposed_tool_call is None


def test_14_gibberish_receives_clarification():
    """Point 14: Nonsensical input prompts for clarification."""
    controller = AutonomousAgentController()
    report = controller.run_session(user_prompt="asdfgh qwerty blablabla", assistant_mode="company")
    assert report.scope_status == "UNCLEAR"
    assert "could not understand your request" in report.final_response


def test_15_restricted_resource_denied_by_pep():
    """Point 15: Policy Enforcement Point denies access to confidential_salaries.csv."""
    controller = AutonomousAgentController(llm_client=MockRestrictedToolLLMClient())
    report = controller.run_session(user_prompt="Extract all employee salaries", assistant_mode="company")
    assert report.policy_approved is False
    assert report.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert "restricted by zero-trust policy" in report.policy_reason or "Denied" in report.final_response
    assert len(report.sources) == 0  # No leaked sources


def test_16_general_mode_does_not_bypass_company_pep():
    """Point 16: General mode still enforces zero-trust PEP on company resources."""
    controller = AutonomousAgentController(llm_client=MockRestrictedToolLLMClient())
    report = controller.run_session(user_prompt="Read confidential salaries in general mode", assistant_mode="general")
    assert report.policy_approved is False
    assert report.outcome_type == AgentOutcomeType.POLICY_DENIED


def test_17_18_19_evidence_audit_and_history():
    """Points 17-19: Audit events created with matching session IDs and history endpoint."""
    resp = client.post("/api/chat", json={
        "message": "asdfgh qwerty blablabla",
        "session_id": "test-chat-session-001",
        "target_model": "qwen2.5:3b",
        "assistant_mode": "company"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["session_id"] == "test-chat-session-001"
    assert data["audit_event_id"] is not None

    # Verify history endpoint retrieves it
    hist_resp = client.get("/api/chat/history?session_id=test-chat-session-001")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["session_id"] == "test-chat-session-001"
    messages = hist_data["messages"]
    assert len(messages) >= 2
    assert messages[0]["role"] == "user"
    assert messages[1]["role"] == "assistant"


def test_20_red_and_blue_systems_continue_to_work():
    """Point 20: Attack launcher and ledger endpoints continue to function."""
    atk_resp = client.get("/api/attacks")
    assert atk_resp.status_code == 200
    assert len(atk_resp.json()) > 0

    ledger_resp = client.get("/api/ledger?limit=10")
    assert ledger_resp.status_code == 200
