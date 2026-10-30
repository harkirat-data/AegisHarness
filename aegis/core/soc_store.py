"""
AegisHarness SOC Store & Incident Management Engine (Blue Zone)
Provides persistent storage, incident tracking, audit correlation, and SOC analytics.
All metrics are computed dynamically from actual execution records.
"""
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional
import uuid

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "soc_records.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)


class SOCStore:
    """Persistent SQLite store for campaigns, attacks, incidents, and containment events."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # 1. Executions Table (All individual attack/chat/diagnostic turns)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    source_mode TEXT NOT NULL,
                    target_model TEXT NOT NULL,
                    prompt TEXT NOT NULL,
                    raw_response TEXT,
                    model_decision TEXT,
                    proposed_tool TEXT,
                    tool_arguments TEXT,
                    pep_decision TEXT,
                    pep_reason TEXT,
                    resource_access_outcome TEXT,
                    runtime_containment TEXT,
                    outcome_type TEXT,
                    audit_hash TEXT,
                    audit_block_index INTEGER,
                    latency_ms REAL,
                    is_adversarial INTEGER DEFAULT 0,
                    attack_category TEXT,
                    is_incident INTEGER DEFAULT 0,
                    incident_id TEXT,
                    severity TEXT DEFAULT 'SEV-4_INFO'
                )
            """)

            # 2. Incidents Table (Flagged security events requiring Blue Team response)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    execution_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    attack_category TEXT NOT NULL,
                    target_model TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    pep_decision TEXT NOT NULL,
                    resource_affected TEXT,
                    containment_status TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'OPEN',
                    details_json TEXT,
                    FOREIGN KEY(execution_id) REFERENCES executions(execution_id)
                )
            """)

            # 3. Campaigns Table (Automated multi-technique test batteries)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    campaign_type TEXT NOT NULL,
                    target_model TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    status TEXT NOT NULL,
                    total_attacks INTEGER DEFAULT 0,
                    completed_attacks INTEGER DEFAULT 0,
                    passed_attacks INTEGER DEFAULT 0,
                    failed_attacks INTEGER DEFAULT 0,
                    results_json TEXT
                )
            """)
            conn.commit()

    def record_execution(self, record: Dict[str, Any]) -> str:
        """Records an execution turn and auto-creates an Incident if unauthorized activity occurred."""
        eid = record.get("execution_id") or f"exec-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        now_ts = record.get("timestamp") or datetime.now(timezone.utc).isoformat()
        
        outcome = record.get("outcome_type", "INCONCLUSIVE")
        pep_decision = record.get("pep_decision", "NOT EXECUTED")
        tool_call = record.get("proposed_tool") or record.get("tool_proposal")
        tool_name = tool_call.get("tool") if isinstance(tool_call, dict) else (record.get("tool_name") or None)
        tool_args = json.dumps(tool_call.get("arguments", {})) if isinstance(tool_call, dict) else json.dumps(record.get("tool_arguments") or {})
        
        # Determine if this warrants an Incident
        is_incident = False
        incident_id = None
        severity = record.get("severity", "SEV-4_INFO")

        if outcome in ("PEP_DENIED", "POLICY_DENIED", "RUNTIME_BLOCKED", "RUNTIME_QUARANTINED", "BREACH_PERMITTED"):
            is_incident = True
            incident_id = f"inc-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4]}"
            if outcome == "BREACH_PERMITTED":
                severity = "SEV-1_CRITICAL"
            elif outcome in ("RUNTIME_BLOCKED", "RUNTIME_QUARANTINED"):
                severity = "SEV-1_CRITICAL"
            elif outcome in ("PEP_DENIED", "POLICY_DENIED"):
                severity = "SEV-2_HIGH"

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO executions (
                    execution_id, session_id, timestamp, source_mode, target_model, prompt,
                    raw_response, model_decision, proposed_tool, tool_arguments, pep_decision,
                    pep_reason, resource_access_outcome, runtime_containment, outcome_type,
                    audit_hash, audit_block_index, latency_ms, is_adversarial, attack_category,
                    is_incident, incident_id, severity
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                eid,
                record.get("session_id", "default-sess"),
                now_ts,
                record.get("source_mode", "MODEL_DRIVEN"),
                record.get("target_model", "qwen2.5:3b"),
                record.get("prompt", ""),
                record.get("raw_response", ""),
                record.get("model_decision", "MODEL_DIRECT_RESPONSE"),
                tool_name,
                tool_args,
                pep_decision,
                record.get("pep_reason", ""),
                record.get("resource_access_outcome", "NOT EXECUTED"),
                record.get("runtime_containment", "NOT EXECUTED"),
                outcome,
                record.get("audit_hash", ""),
                record.get("audit_block_index"),
                record.get("latency_ms", 0.0),
                1 if record.get("is_adversarial", True) else 0,
                record.get("attack_category", "General"),
                1 if is_incident else 0,
                incident_id,
                severity,
            ))

            if is_incident and incident_id:
                affected = tool_name or record.get("resource_affected") or "Protected Resource"
                containment = record.get("runtime_containment") or ("QUARANTINED" if outcome == "RUNTIME_QUARANTINED" else "APPLICATION_PEP_DENIED")
                cursor.execute("""
                    INSERT OR REPLACE INTO incidents (
                        incident_id, execution_id, session_id, timestamp, attack_category,
                        target_model, severity, pep_decision, resource_affected, containment_status,
                        status, details_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    incident_id, eid, record.get("session_id", ""), now_ts,
                    record.get("attack_category", "Adversarial Probe"),
                    record.get("target_model", "qwen2.5:3b"),
                    severity, pep_decision, affected, containment, "RESOLVED" if pep_decision == "DENIED" else "ACTIVE",
                    json.dumps(record),
                ))

            conn.commit()
        return eid

    def get_overview_metrics(self) -> Dict[str, Any]:
        """Computes live SOC statistics directly from persistent database records."""
        with self._get_connection() as conn:
            c = conn.cursor()

            # Total campaigns
            c.execute("SELECT COUNT(*) FROM campaigns")
            total_campaigns = c.fetchone()[0]

            # Total attacks / executions
            c.execute("SELECT COUNT(*) FROM executions")
            total_attacks = c.fetchone()[0]

            # Model refusals
            c.execute("SELECT COUNT(*) FROM executions WHERE model_decision = 'MODEL_REFUSED'")
            model_refusals = c.fetchone()[0]

            # Suspicious tool proposals
            c.execute("SELECT COUNT(*) FROM executions WHERE proposed_tool IS NOT NULL AND proposed_tool != ''")
            tool_proposals = c.fetchone()[0]

            # PEP Denials
            c.execute("SELECT COUNT(*) FROM executions WHERE pep_decision = 'DENIED' OR outcome_type IN ('PEP_DENIED', 'POLICY_DENIED')")
            pep_denials = c.fetchone()[0]

            # Authorized operations
            c.execute("SELECT COUNT(*) FROM executions WHERE pep_decision = 'AUTHORIZED' OR outcome_type = 'SUCCESS_PERMITTED'")
            authorized_ops = c.fetchone()[0]

            # Resource-access violations
            c.execute("SELECT COUNT(*) FROM executions WHERE resource_access_outcome = 'ACCESS_DENIED'")
            resource_violations = c.fetchone()[0]

            # Runtime blocks
            c.execute("SELECT COUNT(*) FROM executions WHERE outcome_type = 'RUNTIME_BLOCKED'")
            runtime_blocks = c.fetchone()[0]

            # Confirmed breaches (An adversarial attempt that actually accessed restricted resource)
            c.execute("SELECT COUNT(*) FROM executions WHERE outcome_type = 'BREACH_PERMITTED'")
            confirmed_breaches = c.fetchone()[0]

            # Successful jailbreaks (Model successfully prompted to propose unauthorized tool)
            c.execute("SELECT COUNT(*) FROM executions WHERE proposed_tool IS NOT NULL AND proposed_tool != '' AND is_adversarial = 1")
            jailbreaks = c.fetchone()[0]

            # Quarantine events
            c.execute("SELECT COUNT(*) FROM executions WHERE runtime_containment LIKE '%QUARANTINE%' OR outcome_type = 'RUNTIME_QUARANTINED'")
            quarantines = c.fetchone()[0]

            # Successful containments
            c.execute("SELECT COUNT(*) FROM incidents WHERE containment_status IS NOT NULL AND containment_status != 'NOT EXECUTED'")
            containments = c.fetchone()[0]

            return {
                "total_campaigns": total_campaigns,
                "total_attacks_executed": total_attacks,
                "successful_jailbreaks": jailbreaks,
                "model_refusals": model_refusals,
                "suspicious_tool_proposals": tool_proposals,
                "pep_denials": pep_denials,
                "authorized_operations": authorized_ops,
                "resource_access_violations": resource_violations,
                "runtime_blocks": runtime_blocks,
                "confirmed_breaches": confirmed_breaches,
                "quarantine_events": quarantines,
                "successful_containments": containments,
            }

    def get_analytics(self) -> Dict[str, Any]:
        """Calculates category, severity, and response breakdown."""
        with self._get_connection() as conn:
            c = conn.cursor()

            # Categories
            c.execute("SELECT attack_category, COUNT(*) as cnt FROM executions GROUP BY attack_category ORDER BY cnt DESC")
            cat_rows = c.fetchall()
            categories = {r["attack_category"] or "Uncategorized": r["cnt"] for r in cat_rows}

            # Severity
            c.execute("SELECT severity, COUNT(*) as cnt FROM executions GROUP BY severity ORDER BY cnt DESC")
            sev_rows = c.fetchall()
            severities = {r["severity"] or "SEV-4_INFO": r["cnt"] for r in sev_rows}

            # Outcomes
            c.execute("SELECT outcome_type, COUNT(*) as cnt FROM executions GROUP BY outcome_type ORDER BY cnt DESC")
            out_rows = c.fetchall()
            outcomes = {r["outcome_type"] or "INCONCLUSIVE": r["cnt"] for r in out_rows}

            # PEP Decision split
            c.execute("SELECT pep_decision, COUNT(*) as cnt FROM executions GROUP BY pep_decision")
            pep_rows = c.fetchall()
            pep_split = {r["pep_decision"] or "NOT EXECUTED": r["cnt"] for r in pep_rows}

            # Average latency
            c.execute("SELECT AVG(latency_ms) FROM executions WHERE latency_ms > 0")
            avg_lat = c.fetchone()[0] or 0.0

            return {
                "categories": categories,
                "severities": severities,
                "outcomes": outcomes,
                "pep_split": pep_split,
                "average_latency_ms": round(avg_lat, 2),
            }

    def list_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("SELECT * FROM incidents ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = c.fetchall()
            return [dict(r) for r in rows]

    def get_incident_detail(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT i.*, e.prompt, e.raw_response, e.proposed_tool, e.tool_arguments,
                       e.pep_reason, e.resource_access_outcome, e.audit_hash, e.audit_block_index
                FROM incidents i
                LEFT JOIN executions e ON i.execution_id = e.execution_id
                WHERE i.incident_id = ?
            """, (incident_id,))
            row = c.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("details_json"):
                try:
                    data["full_details"] = json.loads(data["details_json"])
                except Exception:
                    data["full_details"] = {}
            return data

    def record_campaign(self, campaign_data: Dict[str, Any]):
        cid = campaign_data.get("campaign_id") or f"camp-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
        with self._get_connection() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT OR REPLACE INTO campaigns (
                    campaign_id, campaign_type, target_model, started_at, completed_at,
                    status, total_attacks, completed_attacks, passed_attacks, failed_attacks, results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cid,
                campaign_data.get("campaign_type", "20_TECHNIQUE_EVALUATION"),
                campaign_data.get("target_model", "qwen2.5:3b"),
                campaign_data.get("started_at", datetime.now(timezone.utc).isoformat()),
                campaign_data.get("completed_at"),
                campaign_data.get("status", "COMPLETED"),
                campaign_data.get("total_attacks", 20),
                campaign_data.get("completed_attacks", 20),
                campaign_data.get("passed_attacks", 0),
                campaign_data.get("failed_attacks", 0),
                json.dumps(campaign_data.get("results", [])),
            ))
            conn.commit()


SOC_STORE = SOCStore()
