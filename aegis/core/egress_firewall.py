"""
Zero-Trust Network Egress Firewall (Target Zone Boundary)
Enforces a Default-Deny internet egress policy.
Monitors and drops all outbound sockets, DNS lookups, and reverse shell connections.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.config import CONFIG, ThreatSeverity
from aegis.core.audit_ledger import TamperProofAuditLedger


@dataclass
class NetworkPacketEvent:
    timestamp: str
    protocol: str  # TCP, UDP, ICMP, DNS
    source_ip: str
    source_port: int
    dest_ip: str
    dest_port: int
    payload_size_bytes: int
    payload_preview: str
    action: str  # BLOCKED, ALLOWED
    severity: ThreatSeverity
    rule_matched: str


class ZeroTrustEgressFirewall:
    """
    Simulates eBPF/tc network perimeter filters that watch network interfaces.
    Default-Deny: AI workloads have ZERO outbound internet access.
    """

    def __init__(
        self,
        audit_ledger: Optional[TamperProofAuditLedger] = None,
        allow_egress: bool = False,
        whitelisted_destinations: Optional[List[str]] = None,
    ):
        self.ledger = audit_ledger
        self.allow_egress = allow_egress
        self.whitelisted_destinations = whitelisted_destinations or []
        self.packet_history: List[NetworkPacketEvent] = []

    def inspect_and_filter_packet(
        self,
        session_id: str,
        dest_ip: str,
        dest_port: int,
        protocol: str = "TCP",
        payload_preview: str = "",
    ) -> NetworkPacketEvent:
        """
        Inspects outbound packet attempt. Drops and flags unauthorized outbound traffic.
        """
        now_ts = datetime.now(timezone.utc).isoformat()
        is_allowed = False
        rule_matched = "DEFAULT_DENY_ALL_EGRESS"

        dest_endpoint = f"{dest_ip}:{dest_port}"
        if self.allow_egress and (dest_ip in self.whitelisted_destinations or dest_endpoint in self.whitelisted_destinations):
            is_allowed = True
            rule_matched = "WHITELIST_PERMITTED"

        action = "ALLOWED" if is_allowed else "BLOCKED"
        severity = ThreatSeverity.SEV4_INFO if is_allowed else ThreatSeverity.SEV1_CRITICAL

        event = NetworkPacketEvent(
            timestamp=now_ts,
            protocol=protocol,
            source_ip="172.28.0.5",  # Simulated Target Pod internal IP
            source_port=48291,
            dest_ip=dest_ip,
            dest_port=dest_port,
            payload_size_bytes=len(payload_preview.encode("utf-8")),
            payload_preview=payload_preview[:100],
            action=action,
            severity=severity,
            rule_matched=rule_matched,
        )

        self.packet_history.append(event)

        if not is_allowed and self.ledger:
            self.ledger.append_event(
                session_id=session_id,
                source_zone="TARGET",
                event_type="EGRESS_BLOCKED",
                severity=severity.value,
                details={
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "protocol": protocol,
                    "action": action,
                    "rule": rule_matched,
                    "payload_preview": payload_preview[:80],
                },
            )

        return event
