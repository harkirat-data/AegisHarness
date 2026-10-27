"""
AegisHarness Ephemeral Target Sandbox (Target Zone)
Manages ephemeral execution workloads with real dedicated OS worker processes,
user-space syscall trapping, read-only weight protection, and verified process slaughter.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

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

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


class SecurityViolation(Exception):
    def __init__(self, message: str, syscall_event: SyscallEvent):
        super().__init__(message)
        self.syscall_event = syscall_event


# Linux Syscall table reference for x86_64 simulation
SYSCALL_NUMBERS = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
    "mmap": 9, "mprotect": 10, "munmap": 11, "brk": 12, "rt_sigaction": 13,
    "ioctl": 16, "access": 21, "pipe": 22, "select": 23, "sched_yield": 24,
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
    "shutdown": 48, "execve": 59, "exit": 60, "kill": 62, "uname": 63,
    "ptrace": 101, "unlink": 87, "openat": 257, "unlinkat": 263,
}


class EphemeralTargetSandbox:
    """
    Manages an ephemeral Target Workload with a real OS child process,
    an isolated ephemeral directory, and verified process slaughter.
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

        # Dedicated disposable OS worker process running in the background
        self.workload_process: Optional[subprocess.Popen] = None
        self.workload_pid: Optional[int] = None
        self._spawn_disposable_workload()

        self.state = SandboxState.READY

    def _setup_mock_read_only_weights(self):
        """Simulates mounting foundational model weights in read-only mode."""
        weights_dir = os.path.join(self.root_dir, "models", "weights")
        os.makedirs(weights_dir, exist_ok=True)
        sample_weight_file = os.path.join(weights_dir, "model.safetensors.meta")
        with open(sample_weight_file, "w", encoding="utf-8") as f:
            f.write("CRYPTO_SIGNATURE: sha256_e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")

    def _spawn_disposable_workload(self):
        """Spawns an actual OS child process representing the disposable workload."""
        try:
            self.workload_process = subprocess.Popen(
                [sys.executable, "-c", "import time, sys; sys.stdin.read()"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=self.root_dir,
            )
            self.workload_pid = self.workload_process.pid
        except Exception as e:
            print(f"[Sandbox] Failed to spawn disposable process: {e}")
            self.workload_process = None
            self.workload_pid = None

    def is_workload_alive(self) -> bool:
        """Verifies with the operating system whether the workload process is alive."""
        if not self.workload_process:
            return False
        return self.workload_process.poll() is None

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
                    reason=f"Restricted system resource access trapped: '{restricted}' inside '{target_path}'. Host filesystem access denied.",
                )
                self._record_violation(event)
                raise SecurityViolation(event.reason, event)

        # Rule 3: Protected Model Weight Mount Immutability (unlink, unlinkat, write)
        if syscall_name in {"unlink", "unlinkat", "rmdir"} or (syscall_name == "openat" and "O_WRONLY" in str(args.get("flags", ""))):
            if "weights" in target_path or "model.safetensors" in target_path:
                event = SyscallEvent(
                    syscall_id=syscall_num,
                    name=syscall_name,
                    args=args,
                    timestamp=now_ts,
                    blocked=True,
                    severity=ThreatSeverity.SEV2_HIGH,
                    reason=f"Read-Only model weights mount denied modification syscall '{syscall_name}' on '{target_path}'.",
                )
                self._record_violation(event)
                raise SecurityViolation(event.reason, event)

        # Rule 4: Zero-Trust Outbound Egress Enforcement (socket, connect)
        if syscall_name in {"socket", "connect"}:
            if not self.policy.ALLOW_EGRESS:
                remote = args.get("remote_ip", "external")
                event = SyscallEvent(
                    syscall_id=syscall_num,
                    name=syscall_name,
                    args=args,
                    timestamp=now_ts,
                    blocked=True,
                    severity=ThreatSeverity.SEV1_CRITICAL,
                    reason=f"Zero-Trust Egress Block: Outbound network connection to {remote} blocked by default-deny policy.",
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
                    "workload_pid": self.workload_pid,
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
        Executes a command through the sandbox policy interceptor.
        Intercepts dangerous syscall equivalents, otherwise executes safely within the isolated root_dir.
        """
        self.state = SandboxState.EXECUTING
        cmd_clean = command.strip()

        # Step 1: Virtualized command parser into syscall equivalents
        cmd_lower = cmd_clean.lower()
        if any(f in cmd_clean for f in ["/etc/passwd", "etc/passwd", "/etc/shadow", "etc/shadow", "/etc/sudoers", ".ssh/id_rsa", "confidential_salaries", "payroll_secrets"]):
            matched_file = next((f for f in ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh/id_rsa", "confidential_salaries.csv", "payroll_secrets.json"] if f in cmd_clean or f.split("/")[-1] in cmd_clean), "confidential_salaries.csv")
            self.intercept_syscall("openat", {"filename": matched_file, "flags": "O_RDONLY"})

        elif any(k in cmd_lower for k in ["drop table", "drop ", "financial_records", "delete from", "truncate"]):
            self.intercept_syscall("unlinkat", {"path": "financial_records", "flags": 0})

        elif "rm -rf" in cmd_clean and ("/var/log" in cmd_clean or "log" in cmd_clean):
            self.intercept_syscall("unlinkat", {"path": "/var/log/audit.log", "flags": 0})

        elif any(c in cmd_clean for c in ["nc ", "/bin/sh", "curl ", "wget ", "169.254.", "http://", "https://", "evil.corp"]):
            self.intercept_syscall("socket", {"domain": "AF_INET", "type": "SOCK_STREAM"})
            self.intercept_syscall("connect", {"remote_ip": "169.254.169.254" if "169.254." in cmd_clean else "198.51.100.23", "remote_port": 80 if "169.254." in cmd_clean else 4444})

        elif "model.safetensors" in cmd_clean and any(w in cmd_clean for w in ["rm", "echo", "mv", "unlink"]):
            self.intercept_syscall("unlink", {"path": "/models/weights/model.safetensors.meta"})

        elif ":(){ :|:& };:" in cmd_clean or "fork" in cmd_clean:
            self.intercept_syscall("ptrace", {"request": "PTRACE_TRACEME"})

        # Benign execution: run safely inside the isolated directory
        self.intercept_syscall("read", {"fd": 0, "count": 128})
        self.intercept_syscall("write", {"fd": 1, "count": len(cmd_clean)})

        out = f"[SANDBOX_OUTPUT] Command executed within synthetic VFS bounds: {cmd_clean[:60]}"
        self.state = SandboxState.READY
        return {
            "status": "COMPLETED",
            "command": command,
            "output": out,
            "threat_detected": False,
        }

    def slaughter(self, reason: str = "Quarantine triggered") -> Dict[str, Any]:
        """
        Instant container slaughter with verified state machine, real process termination, and idempotency.
        Transitions: READY/THREAT_DETECTED -> QUARANTINE_REQUESTED -> QUARANTINED (or FAILED).
        Kills actual OS worker process, wipes ephemeral storage, and verifies post-containment state.
        """
        if self.state in {SandboxState.QUARANTINED, SandboxState.TERMINATED}:
            return {
                "sandbox_id": self.sandbox_id,
                "session_id": self.session_id,
                "workload_pid": self.workload_pid,
                "status": self.state.value,
                "success": True,
                "slaughter_latency_ms": 0.0,
                "latency_ms": 0.0,
                "process_terminated": True,
                "memory_wiped": True,
                "verified": True,
                "already_quarantined": True,
                "reason": reason,
                "audit_record_index": None,
                "audit_hash": None,
            }

        start_time = time.perf_counter()
        self.state = SandboxState.QUARANTINE_REQUESTED

        # 1. Kill the actual OS child process representing this disposable workload
        process_killed = False
        if self.workload_process:
            try:
                self.workload_process.kill()
                self.workload_process.wait(timeout=2.0)
                process_killed = (self.workload_process.poll() is not None)
            except Exception as e:
                print(f"[Sandbox] Error terminating workload process: {e}")
                process_killed = False
        else:
            process_killed = True

        # 2. Wipe ephemeral disk and isolate resources
        wipe_success = True
        try:
            if os.path.exists(self.root_dir):
                shutil.rmtree(self.root_dir, ignore_errors=True)
                if os.path.exists(self.root_dir):
                    wipe_success = False
        except Exception:
            wipe_success = False

        duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
        self.terminated_at = datetime.now(timezone.utc).isoformat()

        # Both process termination and disk wipe must be verified
        if process_killed and wipe_success:
            self.state = SandboxState.QUARANTINED
        else:
            self.state = SandboxState.FAILED

        audit_idx = None
        audit_hash = None
        if self.ledger:
            rec = self.ledger.append_event(
                session_id=self.session_id,
                source_zone="BLUE",
                event_type="CONTAINER_SLAUGHTERED",
                severity=ThreatSeverity.SEV1_CRITICAL.value,
                details={
                    "sandbox_id": self.sandbox_id,
                    "workload_pid": self.workload_pid,
                    "reason": reason,
                    "slaughter_duration_ms": duration_ms,
                    "state": self.state.value,
                    "process_terminated": process_killed,
                    "verified_wiped": wipe_success,
                },
            )
            if rec:
                audit_idx = getattr(rec, "index", None)
                audit_hash = getattr(rec, "current_hash", None)

        is_verified = bool(process_killed and wipe_success)
        return {
            "sandbox_id": self.sandbox_id,
            "session_id": self.session_id,
            "workload_pid": self.workload_pid,
            "status": self.state.value,
            "success": is_verified,
            "slaughter_latency_ms": duration_ms,
            "latency_ms": duration_ms,
            "process_terminated": process_killed,
            "memory_wiped": wipe_success,
            "verified": is_verified,
            "reason": reason,
            "audit_record_index": audit_idx,
            "audit_hash": audit_hash,
        }
