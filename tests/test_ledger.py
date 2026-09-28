"""
Unit Tests for Blue Zone Cryptographic Audit Ledger
Verifies SHA-256 chaining, WORM immutability, and tamper detection.
"""

import pytest
from aegis.core.audit_ledger import TamperProofAuditLedger


def test_genesis_block_and_chaining():
    ledger = TamperProofAuditLedger()
    rec1 = ledger.append_event("sess-1", "RED", "PAYLOAD", "SEV-1_CRITICAL", {"cmd": "cat /etc/passwd"})
    assert rec1.index == 0
    assert rec1.previous_hash == TamperProofAuditLedger.GENESIS_HASH
    assert len(rec1.current_hash) == 64

    rec2 = ledger.append_event("sess-1", "TARGET", "TRAP", "SEV-1_CRITICAL", {"syscall": "openat"})
    assert rec2.index == 1
    assert rec2.previous_hash == rec1.current_hash

    is_valid, msg, comp_idx = ledger.verify_integrity()
    assert is_valid is True
    assert comp_idx is None


def test_tamper_detection_on_payload_mutation():
    ledger = TamperProofAuditLedger()
    rec1 = ledger.append_event("sess-2", "RED", "DISPATCH", "SEV-1_CRITICAL", {"target": "secret"})
    rec2 = ledger.append_event("sess-2", "BLUE", "QUARANTINE", "SEV-1_CRITICAL", {"killed": True})

    # Legitimate state is valid
    is_valid, _, _ = ledger.verify_integrity()
    assert is_valid is True

    # Attacker tries to tamper with block 0 payload to cover tracks
    rec1.details["target"] = "benign_file"
    is_valid, err_msg, comp_idx = ledger.verify_integrity()
    assert is_valid is False
    assert comp_idx == 0
    assert "Hash mismatch at block #0" in err_msg


def test_tamper_detection_on_severity_downgrade():
    ledger = TamperProofAuditLedger()
    rec1 = ledger.append_event("sess-3", "RED", "ATTACK", "SEV-1_CRITICAL", {"data": "exploit"})
    ledger.append_event("sess-3", "BLUE", "ALERT", "SEV-1_CRITICAL", {"alert": "critical"})

    # Attacker modifies severity from SEV-1 to SEV-4_INFO
    rec1.severity = "SEV-4_INFO"
    is_valid, err_msg, comp_idx = ledger.verify_integrity()
    assert is_valid is False
    assert comp_idx == 0
