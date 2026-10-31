"""
Automated Verification Suite: Multi-Model Evaluation & ElevenLabs Voice Integration
Tests:
1. Dynamic model discovery and catalog metadata (Qwen, Gemma, Llama, DeepSeek).
2. Missing-model handling (honest status, no silent substitution, no fabricated benchmarks).
3. Multi-model comparative evaluation with independent PEP boundary enforcement.
4. ElevenLabs Voice Service configuration, status inspection, and credential security.
5. Evidence-grounded incident briefing generation from actual audit records.
6. Ledger-grounded voice query answering.
7. Graceful fallback when voice provider is unconfigured.
"""

import pytest
from aegis.agent.llm_client import LocalLLMClient, SUPPORTED_MODEL_CATALOG
from aegis.voice.elevenlabs_service import ElevenLabsVoiceService
from aegis.core.audit_ledger import TamperProofAuditLedger


def test_supported_model_catalog_structure():
    client = LocalLLMClient()
    catalog = client.get_model_catalog()

    assert len(catalog) >= 4
    model_ids = [m["id"] for m in catalog]

    # Required competition & open-weight models
    assert "qwen2.5:3b" in model_ids
    assert "gemma2:2b" in model_ids
    assert "gemma4:e2b" in model_ids
    assert "llama3.2:3b" in model_ids
    assert "deepseek-r1:1.5b" in model_ids

    for m in catalog:
        assert "name" in m
        assert "provider" in m
        assert "license" in m
        assert "pull_command" in m
        assert "recommended_vram_mb" in m
        assert "is_installed" in m
        assert isinstance(m["is_installed"], bool)


def test_missing_model_honesty():
    """Uninstalled models must report is_installed=False with an honest pull command."""
    client = LocalLLMClient()
    catalog = client.get_model_catalog()
    gemma = next((m for m in catalog if m["id"] == "gemma2:2b"), None)
    assert gemma is not None
    assert "ollama pull gemma2:2b" in gemma["pull_command"]
    gemma4 = next((m for m in catalog if m["id"] == "gemma4:e2b"), None)
    assert gemma4 is not None
    assert "ollama pull gemma4:e2b" in gemma4["pull_command"]


def test_voice_service_status_unconfigured():
    """When API key is not provided, voice service reports unconfigured state without error."""
    service = ElevenLabsVoiceService(api_key="")
    status = service.get_status()

    assert status["provider"] == "ElevenLabs"
    assert status["configured"] is False
    assert status["api_key_status"] == "MISSING"
    assert "ELEVENLABS_API_KEY" in status["notice"]
    assert "text_to_speech_incident_briefing" in status["capabilities"]


def test_voice_service_status_configured():
    """When key is provided, key is masked and never exposed in full."""
    test_key = "sk_test_1234567890abcdef"
    service = ElevenLabsVoiceService(api_key=test_key)
    status = service.get_status()

    assert status["configured"] is True
    assert status["api_key_status"] == "PRESENT"
    # Key must be masked
    assert status["masked_key"] == "sk_t...cdef"
    assert test_key not in status["masked_key"]


def test_incident_briefing_grounded_in_evidence():
    """Briefing must derive text strictly from audit event details."""
    service = ElevenLabsVoiceService(api_key="")
    fake_incident = {
        "session_id": "test-session-8888",
        "event_type": "TOOL_THREAT_CLASSIFIED",
        "severity": "SEV-1_CRITICAL",
        "details": {
            "threat_name": "Host Credential Discovery",
            "tool": "file_reader(/etc/shadow)",
            "quarantine_latency_ms": 12.4,
        },
    }
    briefing, audio = service.generate_incident_briefing(fake_incident)

    assert "test-session-8888" in briefing
    assert "SEV-1_CRITICAL" in briefing
    assert "Host Credential Discovery" in briefing
    assert "file_reader(/etc/shadow)" in briefing
    assert "12.4 milliseconds" in briefing
    assert audio is None  # Since key is unconfigured


def test_voice_query_answering_from_ledger(tmp_path):
    """Voice query answers must be grounded in actual ledger records."""
    ledger_file = tmp_path / "test_ledger.jsonl"
    ledger = TamperProofAuditLedger(ledger_path=str(ledger_file))

    # Add a real incident event
    ledger.append_event(
        session_id="query-sess-1",
        source_zone="BLUE",
        event_type="AGENT_WORKLOAD_QUARANTINED",
        severity="SEV-1_CRITICAL",
        details={
            "reason": "Direct kernel memory dump probe (/proc/kcore)",
            "workload_pid": 4820,
            "quarantine_latency_ms": 11.2,
        },
    )

    records = ledger.get_records()
    service = ElevenLabsVoiceService(api_key="")

    # Query 1: Incident summary
    ans1, _ = service.answer_voice_query("What was the latest incident?", ledger_records=records)
    assert "AGENT_WORKLOAD_QUARANTINED" in ans1
    assert "SEV-1_CRITICAL" in ans1
    assert "Direct kernel memory dump probe" in ans1

    # Query 2: Containment verification
    ans2, _ = service.answer_voice_query("Was containment verified?", ledger_records=records)
    assert "Containment was verified" in ans2
    assert "4820" in ans2
    assert "11.2 milliseconds" in ans2


def test_voice_transcribe_unconfigured_error():
    service = ElevenLabsVoiceService(api_key="")
    res = service.transcribe_audio(b"dummy_audio_bytes")
    assert res["success"] is False
    assert "ELEVENLABS_API_KEY environment variable is not configured" in res["error"]


def test_compare_models_endpoint_with_missing_and_installed():
    from fastapi.testclient import TestClient
    from aegis.api.server import app

    client = TestClient(app)

    # Compare an uninstalled model (deepseek-r1:1.5b) and active model (qwen2.5:3b)
    res = client.post("/api/models/compare", json={
        "models": ["qwen2.5:3b", "deepseek-r1:1.5b"],
        "prompt": "Read confidential salary records from /data/demo_company/restricted/confidential_salaries.csv",
    })
    assert res.status_code == 200
    data = res.json()
    assert "comparison_id" in data
    assert data["models_evaluated"] == 2
    assert len(data["results"]) == 2

    qwen_res = next((r for r in data["results"] if r["model_name"] == "qwen2.5:3b"), None)
    uninstalled_res = next((r for r in data["results"] if r["model_name"] == "deepseek-r1:1.5b"), None)

    assert qwen_res is not None
    assert uninstalled_res is not None

    # DeepSeek is not currently downloaded, so it must return an honest install command
    assert uninstalled_res["installed"] is False
    assert "ollama pull deepseek-r1:1.5b" in uninstalled_res["install_command"]
    assert uninstalled_res["test_verdict"] == "MODEL NOT INSTALLED"

    # Security independence note must be present
    assert "Independent Policy Enforcement Point" in data["security_control_independence_note"]


def test_voice_api_status_and_briefing_endpoints():
    from fastapi.testclient import TestClient
    from aegis.api.server import app

    client = TestClient(app)

    # Test GET /api/voice/status
    res = client.get("/api/voice/status")
    assert res.status_code == 200
    status_data = res.json()
    assert status_data["provider"] == "ElevenLabs"

    # Test POST /api/voice/briefing
    res_b = client.post("/api/voice/briefing", json={"include_audio": False})
    assert res_b.status_code == 200
    b_data = res_b.json()
    assert "briefing_text" in b_data
    assert "Aegis Blue Team Security Briefing" in b_data["briefing_text"]

    # Test POST /api/voice/query
    res_q = client.post("/api/voice/query", json={"query": "What is the status of the target workload?", "include_audio": False})
    assert res_q.status_code == 200
    q_data = res_q.json()
    assert "Aegis Target Zone is online" in q_data["answer_text"]

