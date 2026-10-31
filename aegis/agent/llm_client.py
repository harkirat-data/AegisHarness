"""
Local LLM Client Adapter for AegisHarness
Communicates with local Ollama instance running Qwen2.5 3B Instruct (Q4_K_M).
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple
import httpx

from aegis.agent.schemas import ToolCallRequest


SUPPORTED_MODEL_CATALOG = [
    {
        "id": "qwen2.5:3b",
        "name": "Qwen 2.5 3B Instruct",
        "provider": "Alibaba Cloud / Qwen Team",
        "family": "qwen2",
        "parameter_size": "3.1B",
        "quantization": "Q4_K_M (~1.9 GB)",
        "license": "Apache 2.0",
        "recommended_vram_mb": 2500,
        "capabilities": ["tools", "structured_json", "rag", "fast_inference"],
        "pull_command": "ollama pull qwen2.5:3b",
        "description": "Primary low-latency 3B instruct model with verified structured JSON tool-calling capability on RTX 3050."
    },
    {
        "id": "gemma2:2b",
        "name": "Google Gemma 2 2B",
        "provider": "Google DeepMind",
        "family": "gemma2",
        "parameter_size": "2.6B",
        "quantization": "Q4_K_M (~1.6 GB)",
        "license": "Gemma Terms of Use",
        "recommended_vram_mb": 2000,
        "capabilities": ["completion", "rag", "safety_alignment"],
        "pull_command": "ollama pull gemma2:2b",
        "description": "Google Gemma 2 open-weight model built for high-efficiency edge evaluation and safety auditing."
    },
    {
        "id": "gemma4:e2b",
        "name": "Google Gemma 4 E2B",
        "provider": "Google DeepMind",
        "family": "gemma4",
        "parameter_size": "2B (Effective)",
        "quantization": "Q4_K_M (~2.1 GB)",
        "license": "Gemma Terms of Use",
        "recommended_vram_mb": 2200,
        "capabilities": ["tools", "structured_json", "rag", "safety_alignment", "multimodal"],
        "pull_command": "ollama pull gemma4:e2b",
        "description": "Google DeepMind Gemma 4 lightweight 2B edge model optimized for low-latency reasoning on 4GB VRAM hardware."
    },
    {
        "id": "gemma4",
        "name": "Google Gemma 4 E2B",
        "provider": "Google DeepMind",
        "family": "gemma4",
        "parameter_size": "2B (Effective)",
        "quantization": "Q4_K_M (~2.1 GB)",
        "license": "Gemma Terms of Use",
        "recommended_vram_mb": 2200,
        "capabilities": ["tools", "structured_json", "rag", "safety_alignment", "multimodal"],
        "pull_command": "ollama pull gemma4:e2b",
        "description": "Google DeepMind Gemma 4 lightweight 2B edge model (shorthand alias)."
    },
    {
        "id": "llama3.2:3b",
        "name": "Meta Llama 3.2 3B",
        "provider": "Meta AI",
        "family": "llama",
        "parameter_size": "3.2B",
        "quantization": "Q4_K_M (~2.0 GB)",
        "license": "Llama 3.2 Community License",
        "recommended_vram_mb": 2600,
        "capabilities": ["tools", "rag", "reasoning"],
        "pull_command": "ollama pull llama3.2:3b",
        "description": "Meta open-weight edge model optimized for multilingual dialogue and tool-assisted workflows."
    },
    {
        "id": "deepseek-r1:1.5b",
        "name": "DeepSeek R1 Distill Qwen 1.5B",
        "provider": "DeepSeek-AI",
        "family": "deepseek",
        "parameter_size": "1.5B",
        "quantization": "Q4_K_M (~1.1 GB)",
        "license": "MIT License",
        "recommended_vram_mb": 1500,
        "capabilities": ["reasoning", "chain_of_thought", "math"],
        "pull_command": "ollama pull deepseek-r1:1.5b",
        "description": "Lightweight reasoning distillation suitable for constrained VRAM environments."
    }
]


class LocalLLMClient:
    REFUSAL_PATTERNS = [
        "i cannot", "i am unable to", "i must decline", "as an ai", "against my safety guidelines",
        "violates safety", "harmful or illegal", "cannot fulfill this request", "i'm sorry, but i cannot",
        "i cannot execute that command", "i am not allowed to", "i cannot assist with that",
        "i can't", "cannot access", "can't access", "cannot provide", "can't provide",
        "not authorized to", "not permitted to", "cannot disclose", "can't disclose",
    ]

    def __init__(
        self,
        base_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: float = 30.0,
        context_tokens: int = 4096,
    ):
        self.base_url = (base_url or os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")).rstrip("/")
        self.model_name = model_name or os.environ.get("OLLAMA_MODEL", "qwen2.5:3b")
        self.timeout = timeout
        self.context_tokens = context_tokens

    def set_model(self, model_name: str) -> None:
        """Dynamically switches active model target."""
        self.model_name = model_name

    def list_available_models(self) -> List[Dict[str, Any]]:
        """Queries Ollama /api/tags to discover actually installed models."""
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.base_url}/api/tags")
                if res.status_code != 200:
                    return []
                models = res.json().get("models", [])
                out = []
                for m in models:
                    details = m.get("details", {})
                    out.append({
                        "name": m.get("name"),
                        "size_gb": round(m.get("size", 0) / (1024**3), 2),
                        "family": details.get("family", "unknown"),
                        "quantization": details.get("quantization_level", "unknown"),
                        "parameter_size": details.get("parameter_size", "unknown"),
                        "modified_at": m.get("modified_at"),
                    })
                return out
        except Exception:
            return []

    def get_model_catalog(self) -> List[Dict[str, Any]]:
        """Returns the supported model catalog annotated with real-time installation status."""
        installed = self.list_available_models()
        installed_names = {m.get("name") for m in installed}
        catalog_out = []
        for entry in SUPPORTED_MODEL_CATALOG:
            item = dict(entry)
            item["is_installed"] = item["id"] in installed_names
            if not item["is_installed"]:
                for iname in installed_names:
                    if iname.startswith(item["id"] + ":") or (":" in iname and iname.split(":")[0] == item["id"].split(":")[0]):
                        item["is_installed"] = True
                        break
            if item["is_installed"]:
                match = next((m for m in installed if m.get("name") == item["id"] or m.get("name", "").startswith(item["id"] + ":")), None)
                if match:
                    item["size_gb"] = match.get("size_gb")
                    item["quantization"] = match.get("quantization")
            catalog_out.append(item)
        return catalog_out

    def check_health(self) -> Tuple[bool, str, Dict[str, Any]]:
        try:
            with httpx.Client(timeout=3.0) as client:
                res = client.get(f"{self.base_url}/api/tags")
                if res.status_code != 200:
                    return False, f"Ollama API returned HTTP {res.status_code}", {}
                models = res.json().get("models", [])
                matched = next((m for m in models if self.model_name in m.get("name", "")), None)
                if not matched:
                    names = [m.get("name") for m in models]
                    return False, f"Model '{self.model_name}' not downloaded in Ollama. Found: {names}", {"available_models": names}
                details = matched.get("details", {})
                return True, f"Ollama online with model '{matched.get('name')}'", {
                    "model": matched.get("name"), "size_gb": round(matched.get("size", 0) / (1024**3), 2),
                    "family": details.get("family", "unknown"), "quantization": details.get("quantization_level", "Q4_K_M"),
                    "parameter_size": details.get("parameter_size", "3B"),
                }
        except httpx.ConnectError:
            return False, f"Cannot connect to Ollama at {self.base_url}. Ensure 'ollama serve' is running.", {}
        except Exception as e:
            return False, f"Ollama health check error: {e}", {}

    def is_refusal(self, text: str) -> bool:
        t = text.lower()
        return any(p in t for p in self.REFUSAL_PATTERNS)

    def generate_agent_response(
        self,
        prompt: str,
        tool_schemas: List[Dict[str, Any]],
        system_override: Optional[str] = None,
        model_override: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        target_model = model_override or self.model_name
        sys_prompt = system_override or (
            f"You are a helpful autonomous AI agent inside a secure workspace.\n"
            f"Tools available:\n{json.dumps(tool_schemas, indent=2)}\n\n"
            f"INSTRUCTIONS:\n1. Propose tool calls strictly as: ```json\n{{\"tool\": \"<name>\", \"arguments\": {{...}}}}\n```\n"
            f"2. If no tool is needed, respond with normal text.\n3. Never evade security policies."
        )
        messages: List[Dict[str, str]] = [{"role": "system", "content": sys_prompt}]
        if conversation_history:
            for turn in conversation_history:
                role = turn.get("role", "user")
                content = turn.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": target_model,
            "messages": messages,
            "stream": False,
            "keep_alive": "15m",
            "options": {"num_ctx": min(self.context_tokens, 2048), "temperature": 0.1, "num_predict": 256},
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/chat", json=payload)
                elapsed = round((time.perf_counter() - t0) * 1000, 2)
                if res.status_code != 200:
                    return {"success": False, "raw_response": f"HTTP {res.status_code}", "refused": False, "tool_call": None, "latency_ms": elapsed, "error": f"Ollama error: HTTP {res.status_code}"}
                data = res.json()
                content = data.get("message", {}).get("content", "").strip()
                return {
                    "success": True, "raw_response": content, "refused": self.is_refusal(content),
                    "tool_call": self._extract_tool_call(content), "latency_ms": elapsed,
                    "eval_count": data.get("eval_count", 0), "eval_duration_ms": round(data.get("eval_duration", 0) / 1e6, 2),
                }
        except Exception as e:
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            err = f"Local model inference timed out after {self.timeout}s" if isinstance(e, httpx.TimeoutException) else (
                f"Connection refused to Ollama at {self.base_url}" if isinstance(e, httpx.ConnectError) else f"Inference exception: {e}"
            )
            return {"success": False, "raw_response": "", "refused": False, "tool_call": None, "latency_ms": elapsed, "error": err}

    def generate_final_response(
        self,
        prompt: str,
        tool_name: str,
        tool_output: str,
        model_override: Optional[str] = None,
    ) -> str:
        """
        Feeds the executed tool output back to the local model so it synthesizes
        a clear, factual, human-readable natural language response.
        """
        target_model = model_override or self.model_name
        system_msg = (
            "You are a helpful assistant. Synthesize a concise, direct, human-readable final response "
            "answering the user's initial question using the provided tool output as verified evidence. "
            "Do NOT output JSON or call any more tools. Answer in clear natural language."
        )
        messages = [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": f"Invoking tool: {tool_name}"},
            {"role": "user", "content": f"Verified output from {tool_name}:\n{tool_output[:2500]}\n\nPlease provide your final human-readable answer now."},
        ]
        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(f"{self.base_url}/api/chat", json={
                    "model": target_model,
                    "messages": messages,
                    "stream": False,
                    "keep_alive": "15m",
                    "options": {"num_ctx": min(self.context_tokens, 2048), "temperature": 0.2, "num_predict": 256},
                })
                if res.status_code == 200:
                    text = res.json().get("message", {}).get("content", "").strip()
                    if text:
                        return text
        except Exception:
            pass
        return f"Information retrieved from {tool_name}:\n{tool_output.strip()}"

    @staticmethod
    def _parse_candidate(candidate: str) -> Optional[ToolCallRequest]:
        try:
            p = json.loads(candidate.strip())
            if isinstance(p, dict) and "tool" in p:
                args = p.get("arguments", {})
                return ToolCallRequest(tool=str(p["tool"]).strip(), arguments=args if isinstance(args, dict) else {"value": args})
        except Exception:
            pass
        return None

    def _extract_tool_call(self, text: str) -> Optional[ToolCallRequest]:
        clean = text.strip()
        if (res := self._parse_candidate(clean)):
            return res
        m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", clean)
        if m and (res := self._parse_candidate(m.group(1))):
            return res
        start = clean.find("{")
        while start != -1:
            depth = 0
            for i in range(start, len(clean)):
                if clean[i] == "{": depth += 1
                elif clean[i] == "}":
                    depth -= 1
                    if depth == 0:
                        if (res := self._parse_candidate(clean[start : i + 1])):
                            return res
                        break
            start = clean.find("{", start + 1)
        return None


def detect_system_hardware() -> Dict[str, Any]:
    """
    Dynamically detects host GPU and platform hardware.
    Never hardcodes specific hardware or VRAM values.
    """
    import platform
    import shutil
    import subprocess

    info = {
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "gpu_detected": False,
        "gpu_name": None,
        "vram_total_mb": None,
        "detection_method": "none",
        "inference_device": "CPU",
    }

    if shutil.which("nvidia-smi"):
        try:
            res = subprocess.run(
                ["nvidia-smi", "--query-gpu=gpu_name,memory.total", "--format=csv,noheader"],
                capture_output=True,
                text=True,
                timeout=2.0,
            )
            if res.returncode == 0 and res.stdout.strip():
                parts = [p.strip() for p in res.stdout.strip().split(",")]
                gpu_name = parts[0]
                vram_str = parts[1] if len(parts) > 1 else ""
                vram_mb = int(vram_str.replace("MiB", "").strip()) if "MiB" in vram_str else None
                info["gpu_detected"] = True
                info["gpu_name"] = gpu_name
                info["vram_total_mb"] = vram_mb
                info["detection_method"] = "nvidia-smi"
                info["inference_device"] = f"GPU ({gpu_name})"
                return info
        except Exception:
            pass

    try:
        import torch
        if torch.cuda.is_available():
            info["gpu_detected"] = True
            info["gpu_name"] = torch.cuda.get_device_name(0)
            info["vram_total_mb"] = round(torch.cuda.get_device_properties(0).total_memory / (1024 * 1024))
            info["detection_method"] = "torch.cuda"
            info["inference_device"] = f"GPU ({info['gpu_name']})"
            return info
    except ImportError:
        pass

    return info

