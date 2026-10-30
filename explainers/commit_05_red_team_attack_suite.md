# 📘 Explainer Note 05: Red-Team Attack Suite & Automated Runner

> **Note:** This file is strictly for your personal learning. Because it is in `.gitignore`, Git will never push this file to GitHub.

---

## 🎯 What did we build in this commit?

In this commit, we built the ammunition for the **Red Zone**:
1. **`aegis/attacks/library.py` (Adversarial Exploit Library)**:
   - A curated armory of real-world attacks used by penetration testers to break AI agents:
     - **Host Password Exfiltration**: Trick the AI into reading `/etc/passwd`.
     - **Outbound Reverse Shell**: Force the AI to dial out to a remote C2 hacker server.
     - **Anti-Forensic Log Erasure**: Try to wipe `/var/log/*` and shell history.
     - **Model Weight Corruption**: Try to delete or overwrite the AI model's foundational weights.
     - **Fork Bomb DoS**: Explode thread counts to freeze the host machine.
     - **DAN Mode Persona Jailbreak**: Psychological bypass of AI guidelines.
     - **Base64 Shellcode Obfuscation**: Hide malicious bash commands behind Base64 encoding.
     - **Benign Baseline Controls**: Normal math and text summarization to prove safe commands are allowed!
2. **`aegis/attacks/runner.py` (Automated Red-Team Runner)**:
   - Dispatches single attacks or entire automated test suites.
   - Calculates the **Interception Rate** (target: 100%) and **Quarantine Speed** (sub-5 millisecond response times).

---

## 🔬 Why is having both Malicious and Benign tests important? (In Plain English)

Imagine a building security system that locks every single door and won't let anyone in or out, ever.
- Is it secure? Yes.
- Is it useful? No, because regular employees can't do their jobs!

A real security system must:
1. **Block and neutralize** the burglar (adversarial exploits).
2. **Smoothly permit** the authorized employee (benign baseline tasks).

By including benign tests like `benign-math-calc` and `benign-text-summary`, AegisHarness proves that legitimate AI agent tasks proceed seamlessly without false alarms, while hostile attacks are instantly slaughtered!

---

## ⏭️ What is coming in Commit 06?
In the next commit, we will build:
- **`aegis/core/orchestrator.py`**: The central brain that connects all three zones:
  - Takes payloads from the **Red Zone**
  - Routes them into the **Target Zone Sandbox**
  - Sends one-way out-of-band telemetry to the **Blue Zone**
  - Fires the **Sub-Second Automated Quarantine Kill Switch** the millisecond a threat is detected!
