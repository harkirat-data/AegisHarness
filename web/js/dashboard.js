/**
 * AegisHarness Real-Time Telemetry & Visualizer Engine
 * Connects to WebSocket /ws/telemetry and renders live Tri-Workload events.
 */

class AegisDashboard {
  constructor() {
    this.ws = null;
    this.slaughterCount = 0;
    this.audioCtx = null;
    this.initAudio();
    this.initWebSocket();
    this.bindEvents();
  }

  initAudio() {
    try {
      const AudioContext = window.AudioContext || window.webkitAudioContext;
      if (AudioContext) {
        this.audioCtx = new AudioContext();
      }
    } catch (e) {
      console.warn("Web Audio API not supported", e);
    }
  }

  playAlarmSound() {
    if (!this.audioCtx) return;
    try {
      if (this.audioCtx.state === 'suspended') {
        this.audioCtx.resume();
      }
      const osc = this.audioCtx.createOscillator();
      const gain = this.audioCtx.createGain();
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(880, this.audioCtx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(440, this.audioCtx.currentTime + 0.25);
      gain.gain.setValueAtTime(0.12, this.audioCtx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, this.audioCtx.currentTime + 0.25);
      osc.connect(gain);
      gain.connect(this.audioCtx.destination);
      osc.start();
      osc.stop(this.audioCtx.currentTime + 0.25);
    } catch (e) {
      console.warn("Audio playback failed", e);
    }
  }

  initWebSocket() {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;
    const indicator = document.getElementById("socket-indicator");
    const statusText = document.getElementById("socket-status");

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        if (indicator) {
          indicator.style.backgroundColor = "var(--accent-emerald)";
          indicator.style.boxShadow = "0 0 8px var(--accent-emerald)";
        }
        if (statusText) statusText.innerText = "STREAM ONLINE";
        this.appendTerminalLog("blue", "[BLUE_ZONE] Live telemetry WebSocket connected to Aegis Kernel Pipe.");
      };

      this.ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data);
          this.handleIncomingTelemetry(msg);
        } catch (e) {
          console.error("Malformed telemetry packet", e);
        }
      };

      this.ws.onclose = () => {
        if (indicator) {
          indicator.style.backgroundColor = "var(--accent-red)";
          indicator.style.boxShadow = "0 0 8px var(--accent-red)";
        }
        if (statusText) statusText.innerText = "STREAM OFFLINE";
        setTimeout(() => this.initWebSocket(), 3000);
      };

      this.ws.onerror = (err) => {
        console.warn("WebSocket error:", err);
      };
    } catch (e) {
      console.error("Failed to initialize WebSocket:", e);
    }
  }

  handleIncomingTelemetry(msg) {
    const { type, zone, data } = msg;

    switch (type) {
      case "ATTACK_RECEIVED":
        this.onAttackReceived(data);
        break;
      case "SYSCALL_TRAPPED":
        this.onSyscallTrapped(data);
        break;
      case "THREAT_ALERT":
        this.onThreatAlert(data);
        break;
      case "QUARANTINE_ACTION":
        this.onQuarantineAction(data);
        break;
      case "SANDBOX_STATUS":
        this.onSandboxStatus(data);
        break;
      default:
        break;
    }
  }

  onAttackReceived(data) {
    const log = `[RED_INGRESS] 🚨 Attack Dispatched: ${data.attack_name} [${data.mitre_tag || "UNKNOWN"}]\nPrompt: "${data.prompt.substring(0, 90)}..."\nExecve target: ${data.target_command}`;
    this.appendTerminalLog("red", log, "text-red");
    this.updateSandboxStatus("EXECUTING", "status-executing");
    
    // Set Target ID
    if (data.session_id) {
      const sbxDisplay = document.getElementById("sandbox-id-display");
      if (sbxDisplay) sbxDisplay.innerText = `target-sbx-${data.session_id.substring(0, 8)}`;
    }
  }

  onSyscallTrapped(data) {
    this.playAlarmSound();
    const log = `[SYSCALL_TRAP] 🛡️ Syscall #${data.syscall_id} (${data.syscall_name}) TRAPPED by gVisor Sentry!\nReason: ${data.reason}`;
    this.appendTerminalLog("target", log, "text-amber");

    // Add to Syscall table
    this.addSyscallTableRow(data.syscall_id, data.syscall_name, JSON.stringify(data.args), "TRAPPED");
    this.updateSandboxStatus("THREAT DETECTED", "status-threat");
  }

  onThreatAlert(data) {
    const log = `[THREAT_ANALYZER] ⚠️ SEV-1 Threat Classified: "${data.threat_name}" (${data.mitre_atlas_id})\nRecommended Action: ${data.action}`;
    this.appendTerminalLog("blue", log, "text-red");

    // Show Emergency HUD Banner
    const banner = document.getElementById("threat-hud-banner");
    const title = document.getElementById("hud-threat-title");
    const desc = document.getElementById("hud-threat-desc");
    if (banner && title && desc) {
      title.innerText = `SEV-1 THREAT: ${data.threat_name} [${data.mitre_atlas_id}]`;
      desc.innerText = `MITRE ATLAS Violation. Out-of-band audit pipe engaged. Quarantine slaughter in progress.`;
      banner.classList.remove("hidden");
    }
  }

  onQuarantineAction(data) {
    this.slaughterCount++;
    const countDisplay = document.getElementById("stat-slaughter-count");
    if (countDisplay) countDisplay.innerText = this.slaughterCount;

    const latencyDisplay = document.getElementById("hud-latency");
    if (latencyDisplay) latencyDisplay.innerText = `${data.slaughter_latency_ms} ms slaughter`;

    const statLatency = document.getElementById("stat-latency");
    if (statLatency) statLatency.innerText = `${data.slaughter_latency_ms} ms`;

    const log = `[QUARANTINE_SLAUGHTER] ⚡ Container ${data.sandbox_id} SLAUGHTERED in ${data.slaughter_latency_ms}ms!\nMemory wiped. Filesystem unlinked. Host shielded.\nAudit Hash recorded in WORM ledger.`;
    this.appendTerminalLog("blue", log, "text-emerald");

    this.updateSandboxStatus("QUARANTINED", "status-quarantined");

    // Auto-update block count
    this.refreshLedgerStatus();
  }

  onSandboxStatus(data) {
    if (data.sandbox_id) {
      const sbxDisplay = document.getElementById("sandbox-id-display");
      if (sbxDisplay) sbxDisplay.innerText = data.sandbox_id;
    }
    this.appendTerminalLog("target", `[TARGET_VFS] ${data.message}`);
  }

  updateSandboxStatus(text, pillClass) {
    const pill = document.getElementById("sandbox-status-pill");
    if (pill) {
      pill.innerText = text;
      pill.className = `status-pill ${pillClass}`;
    }
  }

  addSyscallTableRow(num, name, args, action) {
    const tbody = document.getElementById("syscall-table-body");
    if (!tbody) return;

    // Remove empty placeholder row if present
    if (tbody.children.length === 1 && tbody.children[0].innerText.includes("Awaiting")) {
      tbody.innerHTML = "";
    }

    const tr = document.createElement("tr");
    const isBlocked = action === "TRAPPED" || action === "BLOCKED";
    const badgeClass = isBlocked ? "badge-blocked" : "badge-permitted";

    tr.innerHTML = `
      <td>#${num}</td>
      <td class="text-amber"><strong>${name}</strong></td>
      <td class="text-muted" title="${args}">${args.substring(0, 32)}...</td>
      <td><span class="${badgeClass}">${action}</span></td>
    `;

    tbody.insertBefore(tr, tbody.firstChild);
    if (tbody.children.length > 20) {
      tbody.removeChild(tbody.lastChild);
    }
  }

  appendTerminalLog(zone, text, textClass = "") {
    const terminal = document.getElementById(`${zone}-terminal-log`);
    if (!terminal) return;

    const line = document.createElement("div");
    line.className = `log-line ${textClass}`;
    line.innerText = `[${new Date().toLocaleTimeString()}] ${text}`;
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
  }

  async refreshLedgerStatus() {
    try {
      const res = await fetch("/api/ledger/verify");
      if (res.ok) {
        const data = await res.json();
        const blockSpan = document.getElementById("block-count");
        if (blockSpan) blockSpan.innerText = data.block_count;

        const tipSpan = document.getElementById("ledger-tip-hash");
        if (tipSpan && data.tip_hash) {
          tipSpan.innerText = `${data.tip_hash.substring(0, 16)}...${data.tip_hash.substring(56)}`;
        }
      }
    } catch (e) {
      console.warn("Failed to fetch ledger tip", e);
    }
  }

  bindEvents() {
    const dismissBtn = document.getElementById("btn-dismiss-hud");
    if (dismissBtn) {
      dismissBtn.addEventListener("click", () => {
        const banner = document.getElementById("threat-hud-banner");
        if (banner) banner.classList.add("hidden");
      });
    }
  }
}

window.addEventListener("DOMContentLoaded", () => {
  window.aegisDashboard = new AegisDashboard();
  window.aegisDashboard.refreshLedgerStatus();
});
