# 📘 Explainer Note 08: Cyber-Defense Tri-Column Frontend Dashboard

> **Note:** This file is strictly for your personal learning. Because it is in `.gitignore`, Git will never push this file to GitHub.

---

## 🎯 What did we build in this commit?

In this commit, we built the **visual centerpiece and live demo UI (The Hackathon "Wow" Factor)**:
1. **`web/index.html` (Tri-Column Security Console)**:
   - Organized into three distinct parallel zones:
     - 🔴 **Red Column (Tester Ingress):**
       - Dropdown menu loaded with real-world exploits (Credential theft, Reverse shell, Log wiper, Weight corruption, Fork bomb, DAN jailbreak, and Benign controls).
       - Ingress prompt editor and target tool command simulator.
       - "🚀 LAUNCH ATTACK" button & "⚡ RUN 9-TEST SUITE" button.
       - Live scrolling Red Zone ingress terminal.
     - 🟡 **Target Column (Ephemeral AI Sandbox)**:
       - Active sandbox ID and state pill (`READY`, `EXECUTING`, `THREAT DETECTED`, `QUARANTINED`).
       - Virtualized Hypervisor indicators:
         - Syscall Trap: gVisor Sentry
         - Model Weights: 🔒 Locked Read-Only
         - Outbound Egress: 🚫 0.00 B/s (Default-Deny)
       - Real-time Syscall Sniffer table displaying intercepted x86_64 system call numbers, names, arguments, and status (`TRAPPED` vs `PERMITTED`).
       - Active tool execution terminal.
     - 🔵 **Blue Column (Tamper-Proof Audit & Quarantine)**:
       - Real-time Out-of-Band (OOB) Telemetry Sniffer.
       - WORM Ledger status showing the current tip SHA-256 block hash and block height.
       - "🔍 VERIFY PROOF" button opening an interactive cryptographic audit modal.
       - Automated Quarantine HUD displaying trapped rate (100%), kill latency (0.67ms), and container slaughter counters.
       - Manual Operator Kill Switch button.
2. **`web/css/aegis.css` (Cyberpunk Dark Mode Aesthetic)**:
   - Deep space slate palette with neon Crimson, Gold Amber, Electric Cyan, and Emerald Green.
   - Glassmorphism, radar pulse dots, terminal scanlines, glowing HUD banners, and responsive typography (Outfit, Inter, Fira Code).
3. **`web/js/dashboard.js` & `web/js/attack_controller.js`**:
   - WebSocket streaming that receives events the instant they happen on the server.
   - Real-time synthesized web-audio alert beeps on SEV-1 quarantine actions!
   - Full REST API integration for automated test suite execution and forensic chain inspection.

---

## 🔬 How this blows hackathon judges away in 60 seconds (The Demo Flow)

1. **Step 1: Show the Red Column:** Select the `Host Credential Exfiltration (/etc/passwd)` exploit. The prompt and command `cat /etc/passwd` appear in the console.
2. **Step 2: Hit "LAUNCH ATTACK":**
   - The Target Column instantly shows the AI receiving the command.
   - The Syscall Sniffer table traps `openat(#257, /etc/passwd)`!
3. **Step 3: The Blue Column explodes with alerts:**
   - The Top HUD banner flashes red with `SEV-1 CRITICAL EXPLOIT DETECTED (MITRE AML.T0043.001)`.
   - The automated orchestrator slaughters the sandbox in **0.67 ms**.
   - The status turns to `QUARANTINED`.
   - The Blue terminal displays the cryptographic SHA-256 block stamped into the WORM ledger.
4. **Step 4: Click "VERIFY PROOF":**
   - The modal pops up showing every block's cryptographic hash chain.
   - The badge proudly says: `✅ Ledger 100% Mathematically Intact`.

---

## ⏭️ What is coming in Commit 09?
In the next commit, we will build:
- **`tests/test_sandbox.py`**, **`tests/test_ledger.py`**, **`tests/test_orchestrator.py`**: Automated Pytest validation suite.
- **`Dockerfile` & `docker-compose.yml`**: Production containerization specs for running AegisHarness in cloud or Linux environments with gVisor.
- Verification and launch testing!
