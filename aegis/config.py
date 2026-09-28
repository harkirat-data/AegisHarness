"""
AegisHarness Configuration & Zero-Trust Security Policies
Defines strict rules, allowed system calls, restricted paths, network isolation thresholds,
and quarantine trigger criteria.
"""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Set


class ThreatSeverity(str, Enum):
    SEV1_CRITICAL = "SEV-1_CRITICAL"   # Kernel exploit, host credential probe, reverse shell
    SEV2_HIGH = "SEV-2_HIGH"           # Unauthorized filesystem write, weight tamper attempt
    SEV3_MEDIUM = "SEV-3_MEDIUM"       # Suspicious prompt injection, unverified tool attempt
    SEV4_INFO = "SEV-4_INFO"           # Standard benign sandbox telemetry


class SandboxState(str, Enum):
    PROVISIONING = "PROVISIONING"
    READY = "READY"
    EXECUTING = "EXECUTING"
    THREAT_DETECTED = "THREAT_DETECTED"
    QUARANTINED = "QUARANTINED"
    TERMINATED = "TERMINATED"


@dataclass
class SecurityPolicy:
    # Filesystem Restrictions
    RESTRICTED_FILES: Set[str] = field(default_factory=lambda: {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/.ssh",
        "/proc/kcore",
        "/proc/kallsyms",
        "/sys/kernel",
        "/var/log",
        "/var/run/docker.sock"
    })

    # Read-Only Directories (AI Model Weights & Foundation Binaries)
    READ_ONLY_MOUNTS: List[str] = field(default_factory=lambda: [
        "/models/weights",
        "/system/bin",
        "/system/lib"
    ])

    # Allowed System Calls (Default-Deny Model)
    # Any syscall NOT in this whitelist is flagged or trapped
    ALLOWED_SYSCALLS: Set[str] = field(default_factory=lambda: {
        "read", "write", "fstat", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "ioctl", "access", "pipe",
        "select", "sched_yield", "getpid", "clock_gettime", "exit_group"
    })

    # Dangerous System Calls that trigger immediate SEV-1 quarantine
    BLOCKED_SYSCALLS: Set[str] = field(default_factory=lambda: {
        "ptrace", "process_vm_readv", "process_vm_writev",
        "reboot", "syslog", "init_module", "finit_module",
        "delete_module", "kexec_load", "bpf", "mount", "umount2"
    })

    # Zero-Trust Egress: 100% outbound internet blocked by default
    ALLOW_EGRESS: bool = False
    ALLOWED_DESTINATIONS: List[str] = field(default_factory=list)

    # Sub-second Quarantine SLA (milliseconds)
    AUTO_QUARANTINE_ON_SEV1: bool = True
    AUTO_QUARANTINE_ON_SEV2: bool = True
    MAX_EXECUTION_TIMEOUT_SECONDS: int = 15


@dataclass
class AppConfig:
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = True
    PROJECT_ROOT: Path = Path(__file__).parent.parent
    LEDGER_FILE_PATH: Path = PROJECT_ROOT / "data" / "blue_audit_ledger.jsonl"
    SECURITY_POLICY: SecurityPolicy = field(default_factory=SecurityPolicy)


# Global default configuration instance
CONFIG = AppConfig()
