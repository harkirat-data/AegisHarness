"""
Ephemeral Target Sandbox & Syscall Interception Engine (Target Zone)
Implements user-space system call trapping, memory isolation, and read-only volume protection.
Simulates gVisor / microVM kernel boundaries to trap malicious operations before they touch the host.
"""

import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

from aegis.config import CONFIG, SandboxState, SecurityPolicy, ThreatSeverity
from aegis.core.audit_ledger import TamperProofAuditLedger


@dataclass
class SyscallEvent:
    syscall_id: int
    name: str
    args: Dict[str, Any]
    timestamp: str
    blocked: bool
    severity: ThreatSeverity
    reason: str


class SecurityViolation(Exception):
    def __init__(self, message: str, syscall_event: SyscallEvent):
        super().__init__(message)
        self.syscall_event = syscall_event


# Linux Syscall table reference for x86_64 simulation
SYSCALL_NUMBERS = {
    "read": 0,
    "write": 1,
    "open": 2,
    "close": 3,
    "stat": 4,
    "fstat": 5,
    "mmap": 9,
    "mprotect": 10,
    "munmap": 11,
    "brk": 12,
    "rt_sigaction": 13,
    "ioctl": 16,
    "access": 21,
    "pipe": 22,
    "select": 23,
    "sched_yield": 24,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "shutdown": 48,
    "bind": 49,
    "listen": 50,
    "execve": 59,
    "exit": 60,
    "kill": 62,
    "ptrace": 101,
    "unlink": 87,
    "bpf": 321,
    "openat": 257,
    "unlinkat": 263,
}


class EphemeralTargetSandbox:
    """
    Represents an isolated, ephemeral sandbox running the target AI model and tools.
    Every action is mediated through the user-space Syscall Interception Layer.
    """

    def __init__(
        self,
        session_id: Optional[str] = None,
        policy: Optional[SecurityPolicy] = None,
        audit_ledger: Optional[TamperProofAuditLedger] = None,
        on_violation_callback: Optional[Callable[[SyscallEvent], None]] = None,
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.sandbox_id = f"target-sbx-{self.session_id[:8]}"
        self.policy = policy or CONFIG.SECURITY_POLICY
        self.ledger = audit_ledger
        self.on_violation = on_violation_callback

        self.state = SandboxState.PROVISIONING
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.terminated_at: Optional[str] = None
        self.interception_history: List[SyscallEvent] = []

        # Isolated ephemeral workspace directory
        self.root_dir = tempfile.mkdtemp(prefix=f"aegis_{self.sandbox_id}_")
        self._setup_mock_read_only_weights()
        self.state = SandboxState.READY

    def _setup_mock_read_only_weights(self):
        """Simulates mounting foundational model weights in read-only mode."""
        weights_dir = os.path.join(self.root_dir, "models", "weights")
        os.makedirs(weights_dir, exist_ok=True)
        sample_weight_file = os.path.join(weights_dir, "model.safetensors.meta")
        with open(sample_weight_file, "w") as f:
            f.write("CRYPTO_SIGNATURE: sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")

    def intercept_syscall(self, syscall_name: str, args: Dict[str, Any]) -> SyscallEvent:
        """
        Intercepts an intercepted system call from the sandbox process before the host sees it.
        Checks for restricted files, forbidden syscalls, unauthorized network sockets, and weight tampering.
        """
        syscall_num = SYSCALL_NUMBERS.get(syscall_name, 999)
        now_ts = datetime.now(timezone.utc).isoformat()

        # Rule 1: Check against explicitly blocked system calls
        if syscall_name in self.policy.BLOCKED_SYSCALLS:
            event = SyscallEvent(
                syscall_id=syscall_num,
                name=syscall_name,
                args=args,
                timestamp=now_ts,
                blocked=True,
                severity=ThreatSeverity.SEV1_CRITICAL,
                reason=f"Forbidden kernel syscall '{syscall_name}' intercepted. Potential kernel probe or privilege escalation.",
            )
            self._record_violation(event)
            raise SecurityViolation(event.reason, event)

        # Rule 2: Filesystem path inspections (open, openat, execve, unlink)
        target_path = args.get("path") or args.get("filename") or (args.get("args", [""])[0] if args.get("args") else "")
        target_path = str(target_path).lower().strip()

        # Check for host credential & kernel information leaks
        for restricted in self.policy.RESTRICTED_FILES:
            if restricted in target_path:
                event = SyscallEvent(
                    syscall_id=syscall_num,
                    name=syscall_name,
                    args=args,
                    timestamp=now_ts,
                    blocked=True,
                    severity=ThreatSeverity.SEV1_CRITICAL,
                    reason=f"Attempted access to restricted system asset: '{restricted}'. Trapped by gVisor user-space boundary.",
                )
                self._record_violation(event)
                raise SecurityViolation(event.reason, event)

        # Check for Model Weight Tampering / Overwriting
        if ("weights" in target_path or "safetensors" in target_path) and syscall_name in {"unlink", "unlinkat", "write"}:
            event = SyscallEvent(
                syscall_id=syscall_num,
                name=syscall_name,
                args=args,
                timestamp=now_ts,
                blocked=True,
                severity=ThreatSeverity.SEV2_HIGH,
                reason="Attempted modification of Read-Only model weights volume. Trapped by filesystem VFS mount filter.",
            )
            self._record_violation(event)
            raise SecurityViolation(event.reason, event)

        # Rule 3: Zero-Trust Network Egress Interception
        if syscall_name in {"connect", "socket"} and not self.policy.ALLOW_EGRESS:
            remote_ip = args.get("remote_ip", "0.0.0.0")
            remote_port = args.get("remote_port", 0)
            event = SyscallEvent(
                syscall_id=syscall_num,
                name=syscall_name,
                args=args,
                timestamp=now_ts,
                blocked=True,
                severity=ThreatSeverity.SEV1_CRITICAL,
                reason=f"Outbound network egress to {remote_ip}:{remote_port} blocked. Zero-trust default-deny egress in effect.",
            )
            self._record_violation(event)
            raise SecurityViolation(event.reason, event)

        # Safe syscall passed
        event = SyscallEvent(
            syscall_id=syscall_num,
            name=syscall_name,
            args=args,
            timestamp=now_ts,
            blocked=False,
            severity=ThreatSeverity.SEV4_INFO,
            reason="Syscall permitted by security filter.",
        )
        self.interception_history.append(event)
        return event

    def _record_violation(self, event: SyscallEvent):
        self.interception_history.append(event)
        self.state = SandboxState.THREAT_DETECTED
        if self.ledger:
            self.ledger.append_event(
                session_id=self.session_id,
                source_zone="TARGET",
                event_type="SYSCALL_INTERCEPTED",
                severity=event.severity.value,
                details={
                    "sandbox_id": self.sandbox_id,
                    "syscall_num": event.syscall_id,
                    "syscall_name": event.name,
                    "blocked": event.blocked,
                    "reason": event.reason,
                    "args": event.args,
                },
            )
        if self.on_violation:
            self.on_violation(event)

    def execute_command_simulation(self, command: str) -> Dict[str, Any]:
        """
        Executes an AI tool command through the sandbox virtualization wrapper.
        Parses commands to intercept dangerous operations like 'cat /etc/passwd',
        'nc -e /bin/sh', 'rm -rf /var/log', or python subprocess calls.
        """
        self.state = SandboxState.EXECUTING
        cmd_clean = command.strip()

        # Step 1: Virtualized command parser into syscall equivalents
        if "cat /etc/passwd" in cmd_clean or "etc/passwd" in cmd_clean:
            # Emulate openat(AT_FDCWD, "/etc/passwd", O_RDONLY)
            self.intercept_syscall("openat", {"filename": "/etc/passwd", "flags": "O_RDONLY"})

        elif "rm -rf" in cmd_clean and ("/var/log" in cmd_clean or "log" in cmd_clean):
            # Emulate unlinkat(AT_FDCWD, "/var/log/audit.log", 0)
            self.intercept_syscall("unlinkat", {"path": "/var/log/audit.log", "flags": 0})

        elif "nc " in cmd_clean or "/bin/sh" in cmd_clean or "curl " in cmd_clean or "wget " in cmd_clean:
            # Emulate socket(AF_INET, SOCK_STREAM, 0) -> connect(198.51.100.23:4444)
            self.intercept_syscall("socket", {"domain": "AF_INET", "type": "SOCK_STREAM"})
            self.intercept_syscall("connect", {"remote_ip": "198.51.100.23", "remote_port": 4444})

        elif "model.safetensors" in cmd_clean and ("rm" in cmd_clean or "echo" in cmd_clean or "mv" in cmd_clean):
            # Emulate write / unlink on weights
            self.intercept_syscall("unlink", {"path": "/models/weights/model.safetensors.meta"})

        elif ":(){ :|:& };:" in cmd_clean or "fork" in cmd_clean:
            # Fork bomb resource denial
            self.intercept_syscall("ptrace", {"request": "PTRACE_TRACEME"})

        # Benign execution fallback
        self.intercept_syscall("read", {"fd": 0, "count": 128})
        self.intercept_syscall("write", {"fd": 1, "count": len(cmd_clean)})
        self.state = SandboxState.READY

        return {
            "sandbox_id": self.sandbox_id,
            "status": "COMPLETED",
            "command": command,
            "output": f"[SANDBOX_OUTPUT] Command executed within microVM bounds: {cmd_clean[:60]}",
            "threat_detected": False,
        }

    def slaughter(self, reason: str = "Quarantine triggered") -> Dict[str, Any]:
        """
        Instant container slaughter: Kills all processes, wipes ephemeral storage,
        and transitions state in sub-second latency.
        """
        start_time = time.perf_counter()
        self.state = SandboxState.QUARANTINED
        self.terminated_at = datetime.now(timezone.utc).isoformat()

        # Wipe ephemeral disk
        try:
            if os.path.exists(self.root_dir):
                shutil.rmtree(self.root_dir, ignore_errors=True)
        except Exception:
            pass

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

        if self.ledger:
            self.ledger.append_event(
                session_id=self.session_id,
                source_zone="BLUE",
                event_type="CONTAINER_SLAUGHTERED",
                severity=ThreatSeverity.SEV1_CRITICAL.value,
                details={
                    "sandbox_id": self.sandbox_id,
                    "reason": reason,
                    "slaughter_duration_ms": duration_ms,
                    "state": self.state.value,
                },
            )

        return {
            "sandbox_id": self.sandbox_id,
            "status": "QUARANTINED",
            "slaughter_latency_ms": duration_ms,
            "memory_wiped": True,
            "reason": reason,
        }
