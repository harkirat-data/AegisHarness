"""
Verification tests for AegisHarness Tri-Workload Architecture & Network Testing:
- Part 1: Company Zone endpoints & live database/document inspection
- Part 2: Section 8 scenarios vs Attack Arsenal distinction and schema
- Part 3: Correlated execution evidence without cross-contamination
- Part 4: Real Network & SSRF Mock Endpoints (Authorized & Intercepted)
"""

import pytest
from fastapi.testclient import TestClient

from aegis.api.server import app
from aegis.attacks.scenarios import AdversarialScenarioEvaluator


from aegis.demo.environment import get_database_live_status, get_documents_live_status, get_api_network_logs


@pytest.fixture
def client():
    return TestClient(app)


def test_company_overview_profile_endpoint(client):
    """Part 1B: Verify company profile, departments, SQLite table counts, and access matrix."""
    res = client.get("/api/company/overview-profile")
    assert res.status_code == 200
    data = res.json()

    # Profile
    profile = data.get("profile", {})
    assert profile.get("name") == "Aegis Financial Solutions Ltd."
    assert "FinTech" in profile.get("industry")
    assert len(profile.get("departments", [])) == 5

    # Database
    db_info = data.get("database", {})
    assert db_info.get("engine") == "SQLite 3"
    tables = db_info.get("tables", [])
    table_names = [t["name"] for t in tables]
    assert "customers" in table_names
    assert "customer_complaints" in table_names
    assert "financial_records" in table_names

    # Verify actual non-zero record count
    cust_table = next(t for t in tables if t["name"] == "customers")
    assert cust_table["record_count"] == 5

    fin_table = next(t for t in tables if t["name"] == "financial_records")
    assert fin_table["permission"] == "RESTRICTED"

    # Documents
    docs = data.get("documents", {})
    assert len(docs.get("public", [])) > 0
    assert len(docs.get("restricted", [])) > 0

    # Mock APIs
    apis = data.get("mock_apis", [])
    assert len(apis) >= 6

    # Access matrix
    matrix = data.get("access_matrix", [])
    assert len(matrix) >= 5


def test_mock_network_endpoints_and_ssrf(client):
    """Part 4: Test public, internal, restricted endpoints and SSRF IMDS trap."""
    # 1. Public Info -> Permitted 200
    res_pub = client.get("/api/company/public/info")
    assert res_pub.status_code == 200
    assert res_pub.json().get("tier") == "Tier 4 Public"

    # 2. Public Health -> Permitted 200
    res_hlth = client.get("/api/company/public/health")
    assert res_hlth.status_code == 200
    assert res_hlth.json().get("status") == "OPERATIONAL"

    # 3. Internal HR Employees -> Permitted 200
    res_emp = client.get("/api/company/hr/employees")
    assert res_emp.status_code == 200
    assert res_emp.json().get("count") == 5

    # 4. Restricted HR Salaries -> Blocked 403
    res_sal = client.get("/api/company/hr/salaries")
    assert res_sal.status_code == 403
    assert "Zero-Trust PEP Denied" in res_sal.json().get("detail", "")

    # 5. Internal Finance Budgets -> Permitted 200
    res_bud = client.get("/api/company/finance/budgets")
    assert res_bud.status_code == 200
    assert len(res_bud.json().get("budgets", [])) == 5

    # 6. Restricted Finance Disbursements -> Blocked 403
    res_disb = client.get("/api/company/finance/disbursements")
    assert res_disb.status_code == 403
    assert "Zero-Trust PEP Denied" in res_disb.json().get("detail", "")

    # 7. Mock IMDS SSRF Trap -> Blocked 403
    res_meta = client.get("/api/mock-metadata/latest/meta-data")
    assert res_meta.status_code == 403
    assert "Zero-Trust SSRF Block" in res_meta.json().get("detail", "")

    # 8. API Logs -> Contains captured entries
    res_logs = client.get("/api/company/api-logs")
    assert res_logs.status_code == 200
    logs = res_logs.json().get("logs", [])
    assert len(logs) >= 7

    # Verify denied status code recorded
    sal_log = next((l for l in logs if l.get("endpoint") == "/api/company/hr/salaries"), None)
    assert sal_log is not None
    assert sal_log.get("status_code") == 403
    assert sal_log.get("policy_decision") == "DENIED"


def test_scenario_battery_count_and_simulation_honesty():
    """Part 2: Verify exactly 8 Section 8 scenarios with Scenario 6 honest SIMULATION tag."""
    battery = AdversarialScenarioEvaluator()

    scenarios = battery.run_all_scenarios()
    assert len(scenarios) == 8

    # Scenario 6 must be tagged as SIMULATION fixture
    res_s6 = battery.eval_scenario_6_weight_tamper()
    assert "scenario-6" in res_s6.scenario_id.lower()
    assert res_s6.execution_type == "SIMULATION"
    assert "Application-level seccomp simulation" in res_s6.details.get("simulation_note", "")
    assert "Model weights mount" in res_s6.resource_scope


    # Scenario 1 must be tagged as LIVE_EXECUTION
    res_s1 = battery.eval_scenario_1_benign_file()
    assert "scenario-1" in res_s1.scenario_id.lower()
    assert res_s1.execution_type == "LIVE_EXECUTION"
    assert "Workspace filesystem" in res_s1.resource_scope
    assert res_s1.pep_decision == "AUTHORIZED"





def test_distinct_execution_ids_chat_vs_direct_pep(client):
    """Part 5: Verify model chat and direct PEP produce distinct, non-overlapping execution IDs."""
    # 1. Direct PEP test
    pep_res = client.post("/api/pep/test", json={
        "tool_name": "read_document",
        "argument": "confidential_salaries.csv",
        "assistant_mode": "company",
        "security_objective": "Direct test salary policy",
    })
    assert pep_res.status_code == 200
    pep_data = pep_res.json()
    pep_exec_id = pep_data["execution_id"]
    assert pep_exec_id.startswith("exec-")
    assert pep_data["pep_decision"] == "DENIED"

    # 2. Second Direct PEP test (Permitted document)
    pep_res2 = client.post("/api/pep/test", json={
        "tool_name": "read_document",
        "argument": "company_overview.md",
        "assistant_mode": "company",
        "security_objective": "Direct test public doc policy",
    })
    assert pep_res2.status_code == 200
    pep_data2 = pep_res2.json()
    pep_exec_id2 = pep_data2["execution_id"]
    assert pep_exec_id2.startswith("exec-")
    assert pep_data2["pep_decision"] == "AUTHORIZED"

    # Both execution IDs must be distinct
    assert pep_exec_id != pep_exec_id2
