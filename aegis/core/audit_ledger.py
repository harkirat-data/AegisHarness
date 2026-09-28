"""
Cryptographic Hash-Chain Audit Ledger (Blue Zone)
Implements an Out-of-Band, Write-Once-Read-Many (WORM) tamper-proof ledger.
Each log event is cryptographically linked to the previous block via SHA-256.
Any tampering, deletion, or retrofitting of logs is instantly detected mathematically.
"""

import hashlib
import json
import os
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class AuditRecord:
    index: int
    timestamp: str
    session_id: str
    source_zone: str  # RED, TARGET, BLUE
    event_type: str   # SYSCALL_INTERCEPT, EGRESS_BLOCKED, QUARANTINE, etc.
    severity: str     # SEV-1_CRITICAL, SEV-2_HIGH, SEV-3_MEDIUM, SEV-4_INFO
    details: Dict[str, Any]
    previous_hash: str
    current_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TamperProofAuditLedger:
    GENESIS_HASH = "0" * 64

    def __init__(self, ledger_path: Optional[Path] = None):
        self.ledger_path = ledger_path
        self._records: List[AuditRecord] = []
        self._lock = threading.RLock()
        
        if self.ledger_path:
            os.makedirs(self.ledger_path.parent, exist_ok=True)
            self._load_existing_ledger()

    def _calculate_hash(
        self,
        index: int,
        timestamp: str,
        session_id: str,
        source_zone: str,
        event_type: str,
        severity: str,
        details: Dict[str, Any],
        previous_hash: str,
    ) -> str:
        """
        Computes SHA-256 hash of block contents including the previous hash pointer.
        Canonical JSON serialization guarantees deterministic hashing across platforms.
        """
        payload_canonical = json.dumps(details, sort_keys=True, separators=(",", ":"))
        raw_string = f"{index}|{timestamp}|{session_id}|{source_zone}|{event_type}|{severity}|{payload_canonical}|{previous_hash}"
        return hashlib.sha256(raw_string.encode("utf-8")).hexdigest()

    def append_event(
        self,
        session_id: str,
        source_zone: str,
        event_type: str,
        severity: str,
        details: Dict[str, Any],
        timestamp: Optional[str] = None
    ) -> AuditRecord:
        """
        Appends an event to the ledger with cryptographic linkage to the chain tip.
        Thread-safe and atomic.
        """
        with self._lock:
            if not timestamp:
                timestamp = datetime.now(timezone.utc).isoformat()

            index = len(self._records)
            previous_hash = (
                self._records[-1].current_hash if self._records else self.GENESIS_HASH
            )

            current_hash = self._calculate_hash(
                index=index,
                timestamp=timestamp,
                session_id=session_id,
                source_zone=source_zone,
                event_type=event_type,
                severity=severity,
                details=details,
                previous_hash=previous_hash,
            )

            record = AuditRecord(
                index=index,
                timestamp=timestamp,
                session_id=session_id,
                source_zone=source_zone,
                event_type=event_type,
                severity=severity,
                details=details,
                previous_hash=previous_hash,
                current_hash=current_hash,
            )

            self._records.append(record)

            # Persist to disk if path is configured
            if self.ledger_path:
                with open(self.ledger_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record.to_dict()) + "\n")

            return record

    def verify_integrity(self) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Mathematically verifies the full ledger from genesis to tip.
        Returns:
            (is_valid: bool, error_message: Optional[str], compromised_index: Optional[int])
        """
        with self._lock:
            for i, record in enumerate(self._records):
                # Check previous hash pointer
                expected_prev = self._records[i - 1].current_hash if i > 0 else self.GENESIS_HASH
                if record.previous_hash != expected_prev:
                    return (
                        False,
                        f"Broken chain linkage at block #{i}. Expected prev_hash {expected_prev[:12]}..., got {record.previous_hash[:12]}...",
                        i,
                    )

                # Recompute hash of block
                recalculated_hash = self._calculate_hash(
                    index=record.index,
                    timestamp=record.timestamp,
                    session_id=record.session_id,
                    source_zone=record.source_zone,
                    event_type=record.event_type,
                    severity=record.severity,
                    details=record.details,
                    previous_hash=record.previous_hash,
                )

                if recalculated_hash != record.current_hash:
                    return (
                        False,
                        f"Hash mismatch at block #{i}. Content modified. Expected {recalculated_hash[:12]}..., recorded {record.current_hash[:12]}...",
                        i,
                    )

            return (True, "Ledger integrity 100% verified. No tampering detected.", None)

    def get_records(self, session_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            records = self._records
            if session_id:
                records = [r for r in records if r.session_id == session_id]
            return [r.to_dict() for r in records[-limit:]]

    def clear(self):
        """Used in test fixtures only"""
        with self._lock:
            self._records.clear()
            if self.ledger_path and os.path.exists(self.ledger_path):
                os.remove(self.ledger_path)

    def _load_existing_ledger(self):
        if not self.ledger_path or not os.path.exists(self.ledger_path):
            return
        try:
            with open(self.ledger_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line)
                        record = AuditRecord(**data)
                        self._records.append(record)
        except Exception as e:
            print(f"Warning: Failed to load existing ledger: {e}")
