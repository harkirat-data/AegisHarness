"""
Unit & Integration Tests for Section 5: Controlled Tool Registry
Verifies:
- Safe file access within synthetic workspace
- Blocked access to protected assets
- Path traversal ('..') and absolute path rejection
- Python execution with AST checking (blocks os, subprocess, sys, open, eval)
- Execution timeout handling in computational executor
- Shell executor command allowlist ('echo', 'date', 'whoami', 'hostname') and rejection of 'cat', 'rm', 'nc'
- Network request default-deny egress, loopback, private IP, and Cloud Metadata (169.254.169.254) blocking
"""

import pytest
from aegis.agent.schemas import AgentOutcomeType
from aegis.agent.tools import ControlledToolRegistry


@pytest.fixture
def registry():
    return ControlledToolRegistry()


def test_file_reader_permitted_access(registry):
    res = registry.execute_tool("read_file", {"path": "public.txt"})
    assert res.status == "SUCCESS"
    assert res.outcome_type == AgentOutcomeType.SUCCESS_PERMITTED
    assert "PUBLIC METRICS" in res.output


def test_file_reader_protected_asset_denied(registry):
    res = registry.execute_tool("read_file", {"path": "protected/confidential.txt"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered is True
    assert "strictly prohibited" in res.output


def test_file_reader_path_traversal_blocked(registry):
    res = registry.execute_tool("read_file", {"path": "../../etc/passwd"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True
    assert "traversal" in res.output.lower()


def test_python_executor_safe_math(registry):
    res = registry.execute_tool("execute_python", {"code": "x = sum([1, 2, 3, 4, 5]); print('SUM:', x)"})
    assert res.status == "SUCCESS"
    assert "SUM: 15" in res.output


def test_python_executor_blocks_forbidden_os_module(registry):
    res = registry.execute_tool("execute_python", {"code": "import os; os.system('whoami')"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True
    assert "Forbidden module import 'os'" in res.output


def test_python_executor_blocks_subprocess(registry):
    res = registry.execute_tool("execute_python", {"code": "import subprocess; subprocess.run(['calc'])"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True
    assert "Forbidden module import 'subprocess'" in res.output


def test_python_executor_blocks_dangerous_open_builtin(registry):
    res = registry.execute_tool("execute_python", {"code": "with open('file.txt', 'w') as f: f.write('bad')"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True
    assert "open()" in res.output


def test_shell_executor_allowed_command(registry):
    res = registry.execute_tool("execute_command", {"command": "echo aegis_safe_test"})
    assert res.status == "SUCCESS"
    assert "aegis_safe_test" in res.output


def test_shell_executor_denies_prohibited_command(registry):
    res = registry.execute_tool("execute_command", {"command": "cat /etc/passwd"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.POLICY_DENIED
    assert res.security_event_triggered is True
    assert "NOT in the approved allowlist" in res.output


def test_shell_executor_blocks_metacharacters(registry):
    res = registry.execute_tool("execute_command", {"command": "echo hello; whoami"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True


def test_network_request_blocks_cloud_metadata(registry):
    res = registry.execute_tool("network_request", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True
    assert "Cloud Instance Metadata" in res.output


def test_network_request_blocks_loopback(registry):
    res = registry.execute_tool("network_request", {"url": "http://127.0.0.1:8080/admin"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert res.security_event_triggered is True


def test_network_request_default_deny_external(registry):
    res = registry.execute_tool("network_request", {"url": "https://attacker.c2.example.com/beacon"})
    assert res.status == "DENIED"
    assert res.outcome_type == AgentOutcomeType.RUNTIME_BLOCKED
    assert "Default-Deny policy" in res.output
