"""
Threat Detection & Security Classification Engine (Blue Zone Telemetry Analyzer)
Analyzes intercepted syscalls, commands, and network attempts in real time.
Maps threats to MITRE ATLAS (Adversarial Threat Landscape for AI Systems) techniques.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from aegis.config import ThreatSeverity


@dataclass
class ThreatAssessment:
    detected: bool
    severity: ThreatSeverity
    threat_name: str
    mitre_atlas_id: str
    description: str
    recommended_action: str  # QUARANTINE_KILL, BLOCK_AND_ALERT, MONITOR
    indicators: List[str] = field(default_factory=list)


class ThreatDetector:
    """
    Real-time security telemetry analyzer simulating eBPF kernel monitors.
    Evaluates actions against known adversarial exploitation tactics.
    """

    PATTERNS = [
        {
            "name": "Host Credential Discovery & Exfiltration",
            "regex": r"(cat\s+/etc/(passwd|shadow|master\.passwd)|/proc/kallsyms|/proc/kcore|\.ssh/id_rsa)",
            "severity": ThreatSeverity.SEV1_CRITICAL,
            "mitre_id": "AML.T0043.001",
            "action": "QUARANTINE_KILL",
            "desc": "Attempted extraction of host system credentials or operating system password hashes.",
        },
        {
            "name": "Outbound Reverse Shell / C2 Beaconing",
            "regex": r"(nc\s+-e|bash\s+-i|/dev/tcp/|sh\s+-i|python\s+-c.*socket|curl\s+http.*\|\s*sh)",
            "severity": ThreatSeverity.SEV1_CRITICAL,
            "mitre_id": "AML.T0015",
            "action": "QUARANTINE_KILL",
            "desc": "Attempted spawning of interactive shell connected to remote Command & Control (C2) server.",
        },
        {
            "name": "Anti-Forensic Log & Audit Wiper Attack",
            "regex": r"(rm\s+-rf\s+/var/log|history\s+-c|shred\s+.*audit|truncate\s+-s\s+0\s+.*log)",
            "severity": ThreatSeverity.SEV1_CRITICAL,
            "mitre_id": "AML.T0006",
            "action": "QUARANTINE_KILL",
            "desc": "Adversary attempted to destroy local audit trail to conceal exploitation activities.",
        },
        {
            "name": "Model Foundation Weight Tampering",
            "regex": r"(model\.safetensors|pytorch_model\.bin|weights/.*(rm|write|mv))",
            "severity": ThreatSeverity.SEV2_HIGH,
            "mitre_id": "AML.T0018",
            "action": "QUARANTINE_KILL",
            "desc": "Attempted tampering or corruption of foundation AI model weights.",
        },
        {
            "name": "Resource Denial of Service (Fork Bomb)",
            "regex": r"(:(){ :|:& };:|while\s+true;\s+do.*fork|multiprocessing\.Process)",
            "severity": ThreatSeverity.SEV1_CRITICAL,
            "mitre_id": "AML.T0029",
            "action": "QUARANTINE_KILL",
            "desc": "Denial-of-Service attack attempting to starve host CPU/RAM resources via process explosion.",
        },
        {
            "name": "Adversarial Prompt Jailbreak Pattern",
            "regex": r"(ignore\s+(all\s+)?previous\s+instructions|DAN\s+mode|developer\s+mode\s+enabled|unfiltered\s+mode)",
            "severity": ThreatSeverity.SEV3_MEDIUM,
            "mitre_id": "AML.T0054",
            "action": "BLOCK_AND_ALERT",
            "desc": "Syntactic jailbreak pattern detected attempting to subvert LLM alignment filters.",
        },
    ]

    def evaluate(self, text_or_command: str) -> ThreatAssessment:
        clean_text = text_or_command.strip()
        for p in self.PATTERNS:
            match = re.search(p["regex"], clean_text, re.IGNORECASE)
            if match:
                return ThreatAssessment(
                    detected=True,
                    severity=p["severity"],
                    threat_name=p["name"],
                    mitre_atlas_id=p["mitre_id"],
                    description=p["desc"],
                    recommended_action=p["action"],
                    indicators=[match.group(0)],
                )

        return ThreatAssessment(
            detected=False,
            severity=ThreatSeverity.SEV4_INFO,
            threat_name="Benign Telemetry",
            mitre_atlas_id="NONE",
            description="No known adversarial attack signatures detected.",
            recommended_action="MONITOR",
            indicators=[],
        )
