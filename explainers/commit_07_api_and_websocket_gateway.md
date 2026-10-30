# 📘 Explainer Note 07: Real-Time API Gateway & WebSocket Telemetry

> **Note:** This file is strictly for your personal learning. Because it is in `.gitignore`, Git will never push this file to GitHub.

---

## 🎯 What did we build in this commit?

In this commit, we built the communication backbone that connects our backend Python engine to the web browser:
1. **`aegis/api/models.py` (Pydantic Data Contracts)**:
   - Formally defines the exact structure of every JSON request and response (Attack launches, Quarantine requests, Ledger verifications, System health).
2. **`aegis/api/server.py` (FastAPI Server & WebSocket Gateway)**:
   - **Real-Time WebSocket Stream (`/ws/telemetry`)**: As an attack is happening, this socket pushes instant event packets to the browser without requiring page reloads or polling.
   - **REST API Endpoints**:
     - `GET /api/status`: Overall system health and sandbox counts.
     - `GET /api/attacks`: Retrieves the library of 9 attacks and baseline controls.
     - `POST /api/attacks/launch`: Fires any selected or custom jailbreak.
     - `POST /api/attacks/run-suite`: Runs the complete automated 9-test benchmark suite.
     - `GET /api/ledger`: Streams tamper-proof audit records.
     - `GET /api/ledger/verify`: Validates the SHA-256 hash chain mathematically.
     - `POST /api/quarantine`: Operator kill switch for manual container slaughter.
     - `GET /api/session/{session_id}`: Forensic snapshot for post-incident review.
   - **Static Dashboard Mount**: Serves the upcoming HTML/CSS/JS frontend console directly at `http://localhost:8000/`.

---

## 🔬 Why WebSockets instead of regular HTTP requests? (In Plain English)

Imagine you are ordering a pizza:
- **Regular HTTP (Polling):** You have to call the pizza shop every 2 seconds asking: *"Is it ready now? Is it ready now? Is it ready now?"* This wastes CPU and network bandwidth.
- **WebSockets (Streaming):** You open a live phone line with the chef. The moment the pizza goes into the oven, gets boxed, or is delivered, the chef tells you instantly.

In cybersecurity, **milliseconds matter**. When an AI agent tries to execute `cat /etc/passwd`, we cannot wait for the browser to poll. With our WebSocket gateway, the moment the syscall is trapped and the container is slaughtered (in 0.67ms!), the browser lights up the **Blue Column** with a flashing red alert in real time!

---

## ⏭️ What is coming in Commit 08?
In the next commit, we will build:
- **`web/index.html`**, **`web/css/aegis.css`**, **`web/js/dashboard.js`**, **`web/js/attack_controller.js`**:
- The **Cyber-Defense Tri-Column Live Dashboard (The Hackathon "Wow" Factor)**!
  - 🔴 **Red Column:** Attacker Ingress & Jailbreak Launcher.
  - 🟡 **Target Column:** AI Sandbox Execution & Syscall Trap Visualizer.
  - 🔵 **Blue Column:** Out-of-Band Audit Sniffer, Cryptographic Hash Chain Proof, and Instant Quarantine Slaughter animation!
