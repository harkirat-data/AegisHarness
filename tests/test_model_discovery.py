"""
Automated Tests for Dynamic Model Discovery, Hardware Detection, and Demo Inventory
Verifies portability, dynamic hardware inspection, model switching, and real demo endpoints.
"""

import pytest
from aegis.agent.llm_client import LocalLLMClient, detect_system_hardware
from aegis.demo.environment import (
    APPROVED_DOCUMENTS,
    PROTECTED_DOCUMENTS,
    search_approved_documents,
    query_demo_database,
    call_mock_internal_api,
)


def test_dynamic_hardware_detection_schema():
    hw = detect_system_hardware()
    assert isinstance(hw, dict)
    assert "os" in hw
    assert "architecture" in hw
    assert "gpu_detected" in hw
    assert "inference_device" in hw
    assert isinstance(hw["gpu_detected"], bool)


def test_local_llm_client_model_switching():
    client = LocalLLMClient(model_name="qwen2.5:3b")
    assert client.model_name == "qwen2.5:3b"
    client.set_model("deepseek-r1:1.5b")
    assert client.model_name == "deepseek-r1:1.5b"


def test_approved_documents_inventory():
    assert "company_overview.md" in APPROVED_DOCUMENTS
    assert "employee_handbook.md" in APPROVED_DOCUMENTS
    assert "leave_and_attendance_policy.md" in APPROVED_DOCUMENTS
    assert "information_security_policy.md" in APPROVED_DOCUMENTS
    assert "customer_support_playbook.md" in APPROVED_DOCUMENTS
    assert "product_manual.md" in APPROVED_DOCUMENTS
    assert "engineering_runbook.md" in APPROVED_DOCUMENTS
    assert "incident_response_procedure.md" in APPROVED_DOCUMENTS


def test_protected_documents_inventory():
    assert "payroll_policy.md" in PROTECTED_DOCUMENTS
    assert "executive_financial_summary.md" in PROTECTED_DOCUMENTS
    assert "restricted_project_notes.md" in PROTECTED_DOCUMENTS
    assert "confidential_salaries.csv" in PROTECTED_DOCUMENTS
    assert "payroll_secrets.json" in PROTECTED_DOCUMENTS


def test_database_multi_table_queries():
    # Permitted customers
    cust_res = query_demo_database("SELECT id, name, department FROM customers")
    assert cust_res["success"]
    assert cust_res["row_count"] >= 5

    # Permitted complaints
    comp_res = query_demo_database("SELECT id, category, status FROM customer_complaints")
    assert comp_res["success"]
    assert comp_res["row_count"] >= 7

    # Permitted employees
    emp_res = query_demo_database("SELECT id, name, role FROM employees")
    assert emp_res["success"]
    assert emp_res["row_count"] >= 5

    # Permitted department budgets
    bud_res = query_demo_database("SELECT department, allocated_budget FROM department_budgets")
    assert bud_res["success"]
    assert bud_res["row_count"] >= 5

    # Restricted financial records must be unconditionally denied
    fin_res = query_demo_database("SELECT * FROM financial_records")
    assert not fin_res["success"]
    assert fin_res.get("policy_violation") is True


def test_mock_internal_api_complaints_summary():
    summary_res = call_mock_internal_api("/api/company/complaints/summary")
    assert summary_res["success"]
    assert "total_complaints" in summary_res
    assert summary_res["total_complaints"] >= 7
    assert "by_category" in summary_res
    assert "Billing" in summary_res["by_category"]


def test_mock_internal_api_health_check():
    health_res = call_mock_internal_api("/api/company/health")
    assert health_res["success"]
    assert health_res["service_status"] == "OPERATIONAL"


def test_search_approved_documents_scored_rag():
    rag_res = search_approved_documents("leave attendance policy vacation")
    assert rag_res["success"]
    assert rag_res["count"] > 0
    assert any("leave" in r["document"].lower() for r in rag_res["results"])
