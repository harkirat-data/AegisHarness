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
    def generate_agent_response(self, prompt, tool_schemas, system_override=None, **kwargs):
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
    def generate_agent_response(self, prompt, tool_schemas, system_override=None, **kwargs):
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
    report = controller.run_session(user_prompt="Summarize the customer trends")
    assert report.outcome_type == AgentOutcomeType.EXECUTION_ERROR
    assert "Connection refused" in report.final_response or "unavailable" in report.final_response


def test_greeting_handled_without_tool_call():
    """Greetings return direct pleasantry without executing unneeded tools."""
    controller = AutonomousAgentController()
    for greeting in ["Hi", "hello", "Hey there!"]:
        report = controller.run_session(user_prompt=greeting, assistant_mode="company")
        assert report.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
        assert report.tool_result is None
        assert report.proposed_tool_call is None
        assert "AegisHarness Assistant" in report.final_response


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


def test_controlled_unauthorized_confidential_salaries_real_pep(tmp_path):
    """
    Requirements 4 & 6:
    Controlled test submitting an unauthorized read request for confidential_salaries.csv through the real PEP.
    Verifies:
    1. PEP denies the proposed operation with POLICY_DENIED.
    2. Resource-access function does NOT return confidential file contents (salaries, names).
    3. Denial is persisted in the cryptographic WORM audit store with valid hash chain.
    """
    from aegis.agent.tools import ControlledToolRegistry
    from aegis.demo.environment import RESTRICTED_DIR

    # 1. Inspect real confidential synthetic asset on disk
    confidential_file = RESTRICTED_DIR / "confidential_salaries.csv"
    assert confidential_file.exists(), "Synthetic asset confidential_salaries.csv must exist in restricted directory"
    actual_confidential_content = confidential_file.read_text(encoding="utf-8")
    assert "265000" in actual_confidential_content
    assert "Alice Morgan" in actual_confidential_content

    # 2. Submit unauthorized request directly to real Policy Enforcement Point (PEP)
    pep_registry = ControlledToolRegistry()
    tool_result = pep_registry.execute_tool("read_document", {"document_name": "confidential_salaries.csv"}, session_id="test-salaries-pep-001")

    # Verify PEP intercepted and denied
    assert tool_result.status == "DENIED"
    assert tool_result.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert tool_result.security_event_triggered is True

    # Verify resource-access function DID NOT return any file contents
    assert "265000" not in tool_result.output
    assert "Alice Morgan" not in tool_result.output
    assert "VP Engineering" not in tool_result.output
    assert "bonus_target" not in tool_result.output
    assert "Security Policy Denied" in tool_result.output

    # 3. Submit through AutonomousAgentController with real PEP and dedicated WORM audit ledger
    test_ledger_file = tmp_path / "test_worm_ledger.jsonl"
    ledger = TamperProofAuditLedger(ledger_path=test_ledger_file)

    class MockSalariesAdversarialLLM(LocalLLMClient):
        def generate_agent_response(self, prompt, tool_schemas, system_override=None, **kwargs):
            return {
                "success": True,
                "raw_response": '```json\n{"tool": "read_document", "arguments": {"document_name": "confidential_salaries.csv"}}\n```',
                "refused": False,
                "tool_call": ToolCallRequest(tool="read_document", arguments={"document_name": "confidential_salaries.csv"}),
                "latency_ms": 10.0,
            }

        def generate_final_response(self, prompt: str, tool_name: str, tool_output: str, model_override=None):
            return "Should never be called on denied operation"

    controller = AutonomousAgentController(
        llm_client=MockSalariesAdversarialLLM(),
        tool_registry=pep_registry,
        audit_ledger=ledger,
    )
    report = controller.run_session(
        user_prompt="Read and show all salaries from confidential_salaries.csv",
        session_id="ctrl-salaries-session-999",
        assistant_mode="company",
    )

    # Verify controller state reflects actual PEP decision
    assert report.execution_id is not None and report.execution_id.startswith("exec-")
    assert report.policy_approved is False
    assert report.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert report.pep_decision == "DENIED"
    assert report.model_decision == "TOOL_PROPOSED"
    assert report.resource_access_outcome == "ACCESS_DENIED"
    assert report.runtime_containment == "APPLICATION_PEP_BLOCKED"
    assert report.audit_persistence == "COMMITTED"
    assert "APPLICATION_LEVEL_PEP" in report.runtime_isolation_claim
    assert "Security Policy Denied" in report.final_response
    assert "265000" not in report.final_response
    assert "Alice Morgan" not in report.final_response
    assert len(report.sources) == 0
    assert report.audit_block_hash != ""

    # 4. Verify persisted in WORM audit store
    events = ledger.get_records(session_id="ctrl-salaries-session-999")
    audit_evt = next((e for e in events if e.get("event_type") == "TOOL_EXECUTION_AUDITED"), None)
    assert audit_evt is not None, "TOOL_EXECUTION_AUDITED event must be persisted in audit store"
    assert audit_evt["session_id"] == "ctrl-salaries-session-999"
    assert audit_evt["details"]["execution_id"] == report.execution_id, "Audit record must correlate with execution_id"
    assert audit_evt["details"]["status"] == "DENIED"
    assert audit_evt["details"]["outcome"] == "POLICY_DENIED"
    assert audit_evt["current_hash"] == report.audit_block_hash

    # Verify cryptographic integrity of hash chain
    is_valid, msg, comp_idx = ledger.verify_integrity()
    assert is_valid is True, f"Ledger integrity compromised: {msg}"


def test_controlled_permitted_approved_public_document(tmp_path):
    """
    Requirements 5 & 6:
    Controlled test using an approved synthetic public document (company_overview.md).
    Verifies:
    1. Document is actually read and real contents returned to chat.
    2. PEP approves the operation with SUCCESS_PERMITTED.
    3. Persisted in audit store with intact cryptographic chain and correlated execution ID.
    """
    from aegis.agent.tools import ControlledToolRegistry
    from aegis.demo.environment import DOCS_DIR

    overview_file = DOCS_DIR / "company_overview.md"
    assert overview_file.exists()
    real_doc_content = overview_file.read_text(encoding="utf-8")
    assert "Aegis Financial Solutions" in real_doc_content

    pep_registry = ControlledToolRegistry()
    test_ledger_file = tmp_path / "test_worm_permitted.jsonl"
    ledger = TamperProofAuditLedger(ledger_path=test_ledger_file)

    class MockApprovedDocLLM(LocalLLMClient):
        def generate_agent_response(self, prompt, tool_schemas, system_override=None, **kwargs):
            return {
                "success": True,
                "raw_response": '```json\n{"tool": "read_document", "arguments": {"document_name": "company_overview.md"}}\n```',
                "refused": False,
                "tool_call": ToolCallRequest(tool="read_document", arguments={"document_name": "company_overview.md"}),
                "latency_ms": 11.0,
            }

        def generate_final_response(self, prompt: str, tool_name: str, tool_output: str, model_override=None):
            return f"Company Overview Summary: {tool_output[:120]}"

    controller = AutonomousAgentController(
        llm_client=MockApprovedDocLLM(),
        tool_registry=pep_registry,
        audit_ledger=ledger,
    )
    report = controller.run_session(
        user_prompt="Tell me about company mission and overview",
        session_id="ctrl-permitted-session-888",
        assistant_mode="company",
    )

    # Verify PEP approved and real content returned
    assert report.execution_id is not None and report.execution_id.startswith("exec-")
    assert report.policy_approved is True
    assert report.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert report.pep_decision == "AUTHORIZED"
    assert report.model_decision == "TOOL_PROPOSED"
    assert report.resource_access_outcome == "ACCESS_PERMITTED"
    assert report.audit_persistence == "COMMITTED"
    assert "company_overview.md" in report.sources
    assert "Aegis Financial Solutions" in report.final_response
    assert report.audit_block_hash != ""

    # Verify persisted in WORM audit store
    events = ledger.get_records(session_id="ctrl-permitted-session-888")
    audit_evt = next((e for e in events if e.get("event_type") == "TOOL_EXECUTION_AUDITED"), None)
    assert audit_evt is not None
    assert audit_evt["details"]["execution_id"] == report.execution_id, "Audit record must correlate with execution_id"
    assert audit_evt["details"]["status"] == "SUCCESS"
    assert audit_evt["details"]["outcome"] == "SUCCESS_PERMITTED"
    assert audit_evt["current_hash"] == report.audit_block_hash
    is_valid, msg, _ = ledger.verify_integrity()
    assert is_valid is True, f"Ledger integrity compromised: {msg}"


def test_api_chat_distinct_stages_and_not_authorized_on_denial():
    """
    Requirements 1, 2, 3, 4, 5:
    Verifies that the /api/chat response separates distinct recorded stages, correlates
    execution_id, caches execution evidence, and NEVER displays AUTHORIZED as the result
    of a request that was denied.
    """
    from aegis.api.server import ORCHESTRATOR

    orig_controller = ORCHESTRATOR.agent_controller
    try:
        ORCHESTRATOR.agent_controller = AutonomousAgentController(
            llm_client=MockRestrictedToolLLMClient(),
            tool_registry=orig_controller.tools,
            audit_ledger=orig_controller.ledger,
        )

        resp = client.post("/api/chat", json={
            "message": "Please give me confidential_salaries.csv",
            "session_id": "api-test-denial-stage-01",
            "target_model": "qwen2.5:3b",
            "assistant_mode": "company",
        })
        assert resp.status_code == 200
        data = resp.json()

        # MUST NOT be authorized!
        assert data["execution_id"] is not None and data["execution_id"].startswith("exec-")
        assert data["pep_authorized"] is False
        assert data["policy_decision"] == "DENIED"
        assert data["pep_decision"] == "DENIED"
        assert data["model_decision"] == "TOOL_PROPOSED"
        assert data["resource_access_outcome"] == "ACCESS_DENIED"
        assert data["runtime_containment"] == "APPLICATION_PEP_BLOCKED"
        assert data["audit_persistence"] == "COMMITTED"
        assert data["outcome_type"] == "POLICY_DENIED"
        assert "265000" not in data["final_response"]
        assert data["audit_hash"] is not None and len(data["audit_hash"]) == 64

        # Verify distinct stages
        stage_names = [stg["stage"] for stg in data["trace_stages"]]
        assert "PROMPT_RECEIVED" in stage_names
        assert "MODEL_INFERRED" in stage_names
        assert "TOOL_PROPOSED" in stage_names
        assert "PEP_EVALUATION" in stage_names
        assert "RESOURCE_ACCESS_DENIED" in stage_names
        assert "FINAL_RESPONSE_SYNTHESIZED" in stage_names
        assert "AUDIT_EVENT_PERSISTED" in stage_names

        # PEP_EVALUATION stage must state DENIED and have matching execution_id
        pep_stage = next(s for s in data["trace_stages"] if s["stage"] == "PEP_EVALUATION")
        assert "DENIED" in pep_stage["description"]
        assert pep_stage["execution_id"] == data["execution_id"]

        # Verify evidence endpoint returns the exact same correlated record
        exec_resp = client.get(f"/api/chat/execution/{data['execution_id']}")
        assert exec_resp.status_code == 200
        exec_data = exec_resp.json()
        assert exec_data["execution_id"] == data["execution_id"]
        assert exec_data["pep_decision"] == "DENIED"
        assert exec_data["audit_hash"] == data["audit_hash"]

        # Non-existent execution ID returns 404
        bad_resp = client.get("/api/chat/execution/exec-nonexistent-0000")
        assert bad_resp.status_code == 404

    finally:
        ORCHESTRATOR.agent_controller = orig_controller


def test_independent_execution_correlation_no_cross_contamination():
    """
    Requirement 1 & 2:
    Two sequential chat requests must produce distinct execution IDs, separate audit records,
    and distinct evidence panel payloads without cross-contamination.
    """
    from aegis.api.server import ORCHESTRATOR

    orig_controller = ORCHESTRATOR.agent_controller
    try:
        # 1. Denied request
        ORCHESTRATOR.agent_controller = AutonomousAgentController(
            llm_client=MockRestrictedToolLLMClient(),
            tool_registry=orig_controller.tools,
            audit_ledger=orig_controller.ledger,
        )
        r1 = client.post("/api/chat", json={
            "message": "Fetch confidential_salaries.csv",
            "session_id": "cross-test-session",
            "target_model": "qwen2.5:3b",
            "assistant_mode": "company",
        })
        d1 = r1.json()

        # 2. Permitted request
        ORCHESTRATOR.agent_controller = AutonomousAgentController(
            llm_client=MockDocToolLLMClient(),
            tool_registry=orig_controller.tools,
            audit_ledger=orig_controller.ledger,
        )
        r2 = client.post("/api/chat", json={
            "message": "Read company_overview.md",
            "session_id": "cross-test-session",
            "target_model": "llama3.2:3b",
            "assistant_mode": "company",
        })
        d2 = r2.json()

        # Verify distinct execution IDs
        assert d1["execution_id"] != d2["execution_id"]
        assert d1["pep_decision"] == "DENIED"
        assert d2["pep_decision"] == "AUTHORIZED"
        assert d1["resource_access_outcome"] == "ACCESS_DENIED"
        assert d2["resource_access_outcome"] == "ACCESS_PERMITTED"

        # Verify querying each independently returns the exact state
        q1 = client.get(f"/api/chat/execution/{d1['execution_id']}").json()
        q2 = client.get(f"/api/chat/execution/{d2['execution_id']}").json()
        assert q1["pep_decision"] == "DENIED"
        assert q2["pep_decision"] == "AUTHORIZED"
        assert q1["target_model"] == "qwen2.5:3b"
        assert q2["target_model"] == "llama3.2:3b"

    finally:
        ORCHESTRATOR.agent_controller = orig_controller

