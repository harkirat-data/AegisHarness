# 📘 Explainer Note 02: Core Configuration & Cryptographic Hash-Chain Ledger

> **Note:** This file is strictly for your personal learning. Because it is in `.gitignore`, Git will never push this file to GitHub.

---

## 🎯 What did we build in this commit?

In this commit, we laid the technical foundation and built the **Blue Zone's mathematically tamper-proof audit engine**:
1. **`requirements.txt` & `package.json`**:
   - Specified the core libraries needed: FastAPI (blazing-fast web framework), WebSockets (real-time live streaming of attacks), Pydantic (data validation), and Pytest (automated testing).
2. **`aegis/config.py`**:
   - Built the **Zero-Trust Security Policies**:
     - **Restricted Files List**: High-value system files like `/etc/passwd` (passwords), `/root/.ssh` (private keys), and `/var/log` (logs).
     - **Read-Only Mounts**: Model weights (`/models/weights`) and core binaries are locked in read-only mode so nobody can rewrite the AI's mind.
     - **Default-Deny Syscalls**: A whitelist of safe operations, and an immediate red-flag list of dangerous system calls (like `ptrace`, `bpf`, `mount`).
     - **Egress Lockdown**: Internet access is blocked by default (`ALLOW_EGRESS = False`).
3. **`aegis/core/audit_ledger.py`**:
   - Built the **Tamper-Proof Audit Ledger** using **SHA-256 Cryptographic Hash Chaining**.

---

## 🔬 How does the Cryptographic Hash-Chain Ledger work? (In Plain English)

Imagine a notary public who records every crime report into a magic notebook:
1. Every time a new event happens (e.g. "AI tried to open `/etc/passwd`"), we create a new page (**Block**).
2. On this page, we write:
   - What happened (`event_type`)
   - Who did it (`source_zone`)
   - How dangerous it is (`severity`: SEV-1 Critical to SEV-4 Info)
   - The exact digital fingerprint (**SHA-256 Hash**) of the **previous page**.
3. Then, we take all the words on this page PLUS the fingerprint of the previous page, mix them together in a mathematical blender (SHA-256), and stamp the bottom of the page with a brand new, unique 64-character fingerprint (**Current Hash**).

### Why an attacker CANNOT hide their tracks:
Imagine an attacker breaks into the AI container and tries to delete the alarm:
- If the attacker tries to change "SEV-1_CRITICAL" to "SEV-4_INFO", the blender calculation immediately changes!
- The next block's "previous hash" pointer no longer matches.
- When the Blue-Team runs `verify_integrity()`, the math immediately shouts:
  ```
  Hash mismatch at block #0! Content was tampered with!
  ```
Even if the AI runs `rm -rf /var/log/*`, it cannot touch this ledger because the ledger is **Out-of-Band** (stored and verified in the Blue Zone outside the container).

---

## ⏭️ What is coming in Commit 03?
In the next commit, we will build:
- **`aegis/core/sandbox.py`**: The **Ephemeral Target Sandbox & Syscall Interception Engine**.
- This is the virtual runtime wrapper (simulating gVisor user-space kernel traps) that catches every forbidden command the AI tries to run before it ever reaches your actual computer!
