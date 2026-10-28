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


def test_tamper_detection_on_event_deletion():
    ledger = TamperProofAuditLedger()
    ledger.append_event("sess-4", "RED", "DISPATCH", "SEV-1_CRITICAL", {"step": 0})
    ledger.append_event("sess-4", "TARGET", "TRAP", "SEV-1_CRITICAL", {"step": 1})
    ledger.append_event("sess-4", "BLUE", "QUARANTINE", "SEV-1_CRITICAL", {"step": 2})

    # Attacker deletes intermediate block 1 to erase breach evidence
    del ledger._records[1]
    is_valid, err_msg, comp_idx = ledger.verify_integrity()
    assert is_valid is False
    assert comp_idx == 1  # Detects index or hash linkage break at position 1


def test_tamper_detection_on_event_reordering():
    ledger = TamperProofAuditLedger()
    ledger.append_event("sess-5", "RED", "EVENT_0", "SEV-4_INFO", {"idx": 0})
    ledger.append_event("sess-5", "TARGET", "EVENT_1", "SEV-1_CRITICAL", {"idx": 1})
    ledger.append_event("sess-5", "BLUE", "EVENT_2", "SEV-4_INFO", {"idx": 2})

    # Swap blocks 1 and 2
    ledger._records[1], ledger._records[2] = ledger._records[2], ledger._records[1]
    is_valid, err_msg, comp_idx = ledger.verify_integrity()
    assert is_valid is False


def test_tamper_detection_on_broken_hash_pointer():
    ledger = TamperProofAuditLedger()
    ledger.append_event("sess-6", "RED", "EVENT_0", "SEV-4_INFO", {"step": 0})
    rec1 = ledger.append_event("sess-6", "TARGET", "EVENT_1", "SEV-1_CRITICAL", {"step": 1})

    # Attacker mutates previous_hash pointer directly
    rec1.previous_hash = "a" * 64
    is_valid, err_msg, comp_idx = ledger.verify_integrity()
    assert is_valid is False
    assert comp_idx == 1

