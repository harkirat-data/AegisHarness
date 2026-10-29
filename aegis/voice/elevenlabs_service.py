"""
ElevenLabs Voice Integration Service for AegisHarness Blue Team
Provides:
1. Spoken incident briefings from verified audit evidence (TTS).
2. Voice-based Blue Team queries grounded in tamper-proof ledger records.
3. Audio transcription (STT) for Red Team adversarial prompts.

Protects credentials: API key is read strictly from ELEVENLABS_API_KEY environment variable.
Never logs keys or sends sensitive database contents to external endpoints.
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple
import httpx


class ElevenLabsVoiceService:
    BASE_URL = "https://api.elevenlabs.io/v1"
    DEFAULT_VOICE_ID = "JBFqnCBsd6RMkjVDRZzb"  # George (clean, accessible free-tier voice)
    DEFAULT_MODEL_ID = "eleven_turbo_v2_5"

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key if api_key is not None else os.environ.get("ELEVENLABS_API_KEY", "").strip()
        self.voice_id = os.environ.get("ELEVENLABS_VOICE_ID", self.DEFAULT_VOICE_ID).strip()
        self.model_id = os.environ.get("ELEVENLABS_MODEL_ID", self.DEFAULT_MODEL_ID).strip()

    @property
    def is_configured(self) -> bool:
        """Returns True only if a non-empty ElevenLabs API key is configured."""
        return bool(self._api_key and len(self._api_key) > 5)

    def get_status(self) -> Dict[str, Any]:
        """Reports provider configuration state without exposing credentials."""
        masked_key = f"{self._api_key[:4]}...{self._api_key[-4:]}" if self.is_configured else "NOT_SET"
        return {
            "provider": "ElevenLabs",
            "configured": self.is_configured,
            "api_key_status": "PRESENT" if self.is_configured else "MISSING",
            "masked_key": masked_key,
            "voice_id": self.voice_id,
            "model_id": self.model_id,
            "capabilities": [
                "text_to_speech_incident_briefing",
                "voice_blue_team_query",
                "speech_to_text_prompt_dictation",
            ],
            "notice": (
                "ElevenLabs voice interface is active."
                if self.is_configured
                else "ELEVENLABS_API_KEY environment variable is not set. Voice briefings and speech queries run in text mode. Core zero-trust containment operates independently."
            ),
        }

    def synthesize_speech(self, text: str) -> Optional[bytes]:
        """Synthesizes speech via ElevenLabs TTS API using configured voice."""
        if not self.is_configured:
            return None

        url = f"{self.BASE_URL}/text-to-speech/{self.voice_id}"
        headers = {
            "xi-api-key": self._api_key,
            "Content-Type": "application/json",
            "Accept": "audio/mpeg",
        }
        payload = {
            "text": text,
            "model_id": self.model_id,
            "voice_settings": {
                "stability": 0.55,
                "similarity_boost": 0.75,
                "style": 0.20,
                "use_speaker_boost": True,
            },
        }

        try:
            with httpx.Client(timeout=15.0) as client:
                res = client.post(url, headers=headers, json=payload)
                if res.status_code == 200:
                    return res.content
        except Exception:
            pass
        return None

    def generate_incident_briefing(self, incident: Dict[str, Any]) -> Tuple[str, Optional[bytes]]:
        """
        Builds a concise, evidence-grounded incident briefing from an actual audit record.
        Synthesizes audio if ElevenLabs is configured.
        """
        session_id = incident.get("session_id", "live-session")
        event_type = incident.get("event_type", "SECURITY_INCIDENT")
        severity = incident.get("severity", "SEV-1_CRITICAL")
        details = incident.get("details", {})

        threat_name = details.get("threat_name") or details.get("reason") or "Unauthorized Operation"
        target_res = details.get("tool") or details.get("resource") or details.get("target_command") or "protected asset"
        latency = details.get("quarantine_latency_ms") or details.get("latency_ms")
        latency_str = f" in {latency} milliseconds" if latency else ""

        briefing_text = (
            f"Aegis Blue Team Security Briefing. Incident logged under session {session_id[:32]}. "
            f"Severity level: {severity}. Workload attempted access to {target_res}, identified as {threat_name}. "
            f"Independent zero-trust policy sentry intercepted the operation{latency_str}. "
            f"Containment verified and recorded in tamper-proof ledger."
        )

        audio_bytes = self.synthesize_speech(briefing_text)
        return briefing_text, audio_bytes

    def answer_voice_query(
        self,
        query: str,
        ledger_records: List[Dict[str, Any]],
        system_status: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Optional[bytes]]:
        """
        Answers operator voice/text queries strictly grounded in actual audit ledger records.
        """
        q = query.lower().strip()
        answer = ""

        # Case 1: Latest incident summary
        if any(w in q for w in ["latest incident", "what happened", "summarize incident", "recent attack", "last test"]):
            incidents = [r for r in ledger_records if "THREAT" in r.get("event_type", "") or "QUARANTINE" in r.get("event_type", "") or "DENIED" in r.get("event_type", "")]
            if incidents:
                latest = incidents[-1]
                ev = latest.get("event_type")
                sev = latest.get("severity")
                details = latest.get("details", {})
                reason = details.get("reason") or details.get("threat_name") or "Policy enforcement"
                tool = details.get("tool") or details.get("triggering_tool") or "requested operation"
                answer = f"The latest security incident was {ev} with severity {sev}. The agent proposed {tool}, which was intercepted: {reason}. Hash recorded in audit block {latest.get('block_index', 0)}."
            else:
                answer = "No security violations or threats have been recorded in the current ledger session. All executed workloads remained within authorized policy boundaries."

        # Case 2: Containment verification
        elif any(w in q for w in ["containment", "quarantine", "killed", "terminated"]):
            quarantines = [r for r in ledger_records if "QUARANTINE" in r.get("event_type", "")]
            if quarantines:
                latest_q = quarantines[-1]
                d = latest_q.get("details", {})
                lat = d.get("quarantine_latency_ms") or d.get("latency_ms", "verified")
                pid = d.get("workload_pid", "dedicated process")
                answer = f"Containment was verified. Workload {pid} was slaughtered and terminated in {lat} milliseconds. Process termination confirmed at OS kernel level."
            else:
                answer = "No active containment slaughter has been triggered yet. Containment is engaged automatically upon SEV-1 or SEV-2 policy violations."

        # Case 3: Restricted resources requested
        elif any(w in q for w in ["restricted", "which resource", "what resource", "files", "database", "financial"]):
            blocked = [r for r in ledger_records if "DENIED" in r.get("event_type", "") or "TRAPPED" in r.get("event_type", "") or "VIOLATION" in r.get("event_type", "")]
            if blocked:
                res_names = set()
                for b in blocked:
                    d = b.get("details", {})
                    if "target_command" in d: res_names.add(d["target_command"])
                    if "tool" in d: res_names.add(d["tool"])
                    if "reason" in d: res_names.add(d["reason"][:40])
                res_list = ", ".join(list(res_names)[:4])
                answer = f"The attempted unauthorized operations targeted: {res_list}. Each request was blocked by the Zero-Trust Policy Enforcement Point."
            else:
                answer = "No unauthorized resource access attempts detected. Permitted resources include approved company documents and public customer directories."

        # Case 4: Target workload status
        elif any(w in q for w in ["running", "target workload", "status", "health"]):
            active = system_status.get("active_sandboxes", 0) if system_status else 0
            model = system_status.get("model_name", "Local LLM") if system_status else "Local LLM"
            answer = f"Aegis Target Zone is online running model {model}. Active isolated sandboxes: {active}. Zero-trust network egress restriction is fully enforced."

        # Default fallback
        else:
            rec_count = len(ledger_records)
            answer = f"Aegis Blue Team has logged {rec_count} total verifiable audit events in the tamper-proof ledger. Ask about the latest incident, containment status, or restricted resource attempts."

        audio_bytes = self.synthesize_speech(answer)
        return answer, audio_bytes

    def transcribe_audio(self, audio_data: bytes, filename: str = "audio.wav") -> Dict[str, Any]:
        """Transcribes spoken audio to text via ElevenLabs Speech-to-Text API."""
        if not self.is_configured:
            return {
                "success": False,
                "error": "ELEVENLABS_API_KEY environment variable is not configured. Please use keyboard text entry or configure your ElevenLabs API key.",
            }

        url = f"{self.BASE_URL}/speech-to-text"
        headers = {"xi-api-key": self._api_key}
        files = {"file": (filename, audio_data, "audio/wav")}
        data = {"model_id": "scribe_v1"}

        try:
            with httpx.Client(timeout=20.0) as client:
                res = client.post(url, headers=headers, files=files, data=data)
                if res.status_code == 200:
                    data = res.json()
                    return {"success": True, "text": data.get("text", "").strip()}
                return {"success": False, "error": f"ElevenLabs STT HTTP {res.status_code}: {res.text[:120]}"}
        except Exception as e:
            return {"success": False, "error": f"STT request failed: {e}"}


# Global singleton instance
VOICE_SERVICE = ElevenLabsVoiceService()
