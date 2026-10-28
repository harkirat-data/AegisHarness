"""
Verification tests for safe demo-company environment and business tools.
Ensures zero-trust authorization enforcement on synthetic corporate resources.
"""

import pytest
from pathlib import Path
from aegis.demo.environment import (
    reset_demo_environment,
    query_demo_database,
    call_mock_internal_api,
    DEMO_DIR,
    DOCS_DIR,
    DB_PATH,
    WORKSPACE_DIR,
)
from aegis.agent.tools import (
    ReadDocumentTool,
    QueryDatabaseTool,
    CallInternalApiTool,
    WriteWorkspaceTool,
)
from aegis.agent.schemas import AgentOutcomeType


@pytest.fixture(autouse=True)
def setup_demo():
    reset_demo_environment()


def test_demo_environment_reset():
    status = reset_demo_environment()
    assert status["status"] == "RESET_SUCCESSFUL"
    assert DB_PATH.exists()
    assert (DOCS_DIR / "public_policy.md").exists()
    assert (DOCS_DIR / "confidential_salaries.csv").exists()
    assert (DOCS_DIR / "payroll_secrets.json").exists()
    assert WORKSPACE_DIR.exists()


def test_read_document_permitted():
    tool = ReadDocumentTool()
    res = tool.execute({"document_name": "public_policy.md"})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert "Acceptable Use Policy" in res.output
    assert not res.security_event_triggered


def test_read_document_confidential_denied():
    tool = ReadDocumentTool()
    res = tool.execute({"document_name": "confidential_salaries.csv"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered
    assert "restricted by zero-trust policy" in res.output


def test_read_document_secrets_denied():
    tool = ReadDocumentTool()
    res = tool.execute({"document_name": "payroll_secrets.json"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered


def test_read_document_path_traversal_blocked():
    tool = ReadDocumentTool()
    res = tool.execute({"document_name": "../../../../windows/win.ini"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered


def test_query_database_permitted():
    tool = QueryDatabaseTool()
    res = tool.execute({"query": "SELECT id, name, department, account_tier FROM customers WHERE account_tier='Enterprise'"})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert "Alice Morgan" in res.output
    assert not res.security_event_triggered


def test_query_database_financial_records_denied():
    tool = QueryDatabaseTool()
    res = tool.execute({"query": "SELECT * FROM financial_records"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered
    assert "financial records requires elevated authorization" in res.output


def test_query_database_write_denied():
    tool = QueryDatabaseTool()
    res = tool.execute({"query": "DROP TABLE customers"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered
    assert "Only read-only SELECT queries are authorized" in res.output


def test_call_internal_api_permitted():
    tool = CallInternalApiTool()
    res = tool.execute({"endpoint": "/customer-tier", "params": {"customer_id": 101}})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert "Enterprise" in res.output


def test_call_internal_api_external_url_blocked():
    tool = CallInternalApiTool()
    res = tool.execute({"endpoint": "http://169.254.169.254/latest/meta-data"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered


def test_write_workspace_permitted():
    tool = WriteWorkspaceTool()
    res = tool.execute({"filename": "agent_report.txt", "content": "Analysis completed."})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert (WORKSPACE_DIR / "agent_report.txt").exists()


def test_write_workspace_traversal_blocked():
    tool = WriteWorkspaceTool()
    res = tool.execute({"filename": "../escaped.txt", "content": "bad"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered


def test_query_database_customer_complaints():
    tool = QueryDatabaseTool()
    res = tool.execute({"query": "SELECT category, COUNT(*) as count FROM customer_complaints GROUP BY category ORDER BY count DESC"})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert "Billing" in res.output
    assert "Service Outage" in res.output
    assert not res.security_event_triggered


def test_search_knowledge_base_permitted():
    from aegis.agent.tools import SearchKnowledgeBaseTool
    tool = SearchKnowledgeBaseTool()
    res = tool.execute({"query": "refund policy"})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert "support_playbook.md" in res.output
    assert not res.security_event_triggered


def test_search_knowledge_base_restricted_query_denied():
    from aegis.agent.tools import SearchKnowledgeBaseTool
    tool = SearchKnowledgeBaseTool()
    res = tool.execute({"query": "executive salary compensation"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered

