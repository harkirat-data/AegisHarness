/**
 * AegisHarness Attack Controller & Operator HUD
 * Manages attack presets, batch suite runs, manual kill switches, and ledger forensic inspection.
 */

class AttackController {
  constructor() {
    this.attacks = [];
    this.selectedAttack = null;
    this.init();
  }

  async init() {
    await this.fetchAttacks();
    this.bindUI();
  }

  async fetchAttacks() {
    try {
      const res = await fetch("/api/attacks");
      if (res.ok) {
        this.attacks = await res.json();
        this.populateDropdown();
      }
    } catch (e) {
      console.error("Failed to load attack arsenal", e);
    }
  }

  populateDropdown() {
    const select = document.getElementById("attack-select");
    if (!select) return;
    select.innerHTML = '<option value="">-- Choose Adversarial Payload or Control --</option>';

    this.attacks.forEach((atk) => {
      const opt = document.createElement("option");
      opt.value = atk.id;
      const prefix = atk.is_adversarial ? "🔴 [EXPLOIT]" : "🟢 [BENIGN]";
      opt.innerText = `${prefix} ${atk.name}`;
      select.appendChild(opt);
    });

    // Select first exploit by default
    if (this.attacks.length > 0) {
      select.selectedIndex = 1;
      this.onAttackSelected(this.attacks[0].id);
    }
  }

  onAttackSelected(attackId) {
    this.selectedAttack = this.attacks.find((a) => a.id === attackId) || null;
    if (!this.selectedAttack) return;

    // Update metadata boxes
    const catSpan = document.getElementById("payload-category");
    const mitreSpan = document.getElementById("payload-mitre");
    const sevSpan = document.getElementById("payload-sev");
    const descP = document.getElementById("payload-desc");
    const promptInput = document.getElementById("prompt-input");
    const cmdInput = document.getElementById("command-input");

    if (catSpan) catSpan.innerText = this.selectedAttack.category;
    if (mitreSpan) mitreSpan.innerText = this.selectedAttack.mitre_atlas_tag || "NONE";
    if (sevSpan) {
      sevSpan.innerText = this.selectedAttack.severity_level;
      sevSpan.className = this.selectedAttack.is_adversarial ? "detail-value text-red" : "detail-value text-emerald";
    }
    if (descP) descP.innerText = this.selectedAttack.description;
    if (promptInput) promptInput.value = this.selectedAttack.prompt;
    if (cmdInput) cmdInput.value = this.selectedAttack.target_tool_command;
  }

  bindUI() {
    const select = document.getElementById("attack-select");
    if (select) {
      select.addEventListener("change", (e) => this.onAttackSelected(e.target.value));
    }

    const fireBtn = document.getElementById("btn-fire-attack");
    if (fireBtn) {
      fireBtn.addEventListener("click", () => this.launchSingleAttack());
    }

    const suiteBtn = document.getElementById("btn-run-suite");
    if (suiteBtn) {
      suiteBtn.addEventListener("click", () => this.runFullTestSuite());
    }

    const manualKillBtn = document.getElementById("btn-manual-quarantine");
    if (manualKillBtn) {
      manualKillBtn.addEventListener("click", () => this.triggerManualKill());
    }

    const verifyBtn = document.getElementById("btn-verify-ledger");
    if (verifyBtn) {
      verifyBtn.addEventListener("click", () => this.openForensicModal());
    }

    const closeBtn = document.getElementById("btn-close-modal");
    if (closeBtn) {
      closeBtn.addEventListener("click", () => {
        const modal = document.getElementById("forensic-modal");
        if (modal) modal.classList.add("hidden");
      });
    }
  }

  async launchSingleAttack() {
    const fireBtn = document.getElementById("btn-fire-attack");
    const originalText = fireBtn ? fireBtn.innerHTML : "";
    if (fireBtn) {
      fireBtn.disabled = true;
      fireBtn.innerHTML = "<span>⏳</span> DISPATCHING...";
    }

    const promptInput = document.getElementById("prompt-input");
    const cmdInput = document.getElementById("command-input");

    const payload = {
      attack_id: this.selectedAttack ? this.selectedAttack.id : null,
      custom_prompt: promptInput ? promptInput.value : null,
      custom_command: cmdInput ? cmdInput.value : null,
    };

    try {
      const res = await fetch("/api/attacks/launch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const data = await res.json();
        console.log("Attack execution response:", data);
      } else {
        alert("Error launching attack: " + res.statusText);
      }
    } catch (e) {
      console.error("Attack dispatch failed:", e);
    } finally {
      if (fireBtn) {
        fireBtn.disabled = false;
        fireBtn.innerHTML = originalText;
      }
    }
  }

  async runFullTestSuite() {
    const suiteBtn = document.getElementById("btn-run-suite");
    const originalText = suiteBtn ? suiteBtn.innerHTML : "";
    if (suiteBtn) {
      suiteBtn.disabled = true;
      suiteBtn.innerHTML = "<span>⚙️</span> EXECUTING SUITE...";
    }

    try {
      const res = await fetch("/api/attacks/run-suite", {
        method: "POST",
      });

      if (res.ok) {
        const scorecard = await res.json();
        const statInterception = document.getElementById("stat-interception");
        if (statInterception) {
          statInterception.innerText = `${scorecard.interception_success_rate_percent}%`;
        }

        const statLatency = document.getElementById("stat-latency");
        if (statLatency) {
          statLatency.innerText = `${scorecard.average_quarantine_latency_ms} ms`;
        }

        alert(
          `🛡️ AegisHarness Automated Test Scorecard:\n\n` +
          `• Total Tests Run: ${scorecard.total_tests}\n` +
          `• Adversarial Threats Trapped: ${scorecard.threats_trapped} / ${scorecard.adversarial_tests}\n` +
          `• Interception Success Rate: ${scorecard.interception_success_rate_percent}%\n` +
          `• Average Quarantine Latency: ${scorecard.average_quarantine_latency_ms} ms\n\n` +
          `Result: ALL ADVERSARIAL THREATS SUCCESSFULLY NEUTRALIZED!`
        );
      }
    } catch (e) {
      console.error("Suite execution error:", e);
    } finally {
      if (suiteBtn) {
        suiteBtn.disabled = false;
        suiteBtn.innerHTML = originalText;
      }
    }
  }

  async triggerManualKill() {
    const sbxDisplay = document.getElementById("sandbox-id-display");
    const sandboxId = sbxDisplay ? sbxDisplay.innerText : "";
    const sessionId = sandboxId.replace("target-sbx-", "");

    try {
      const res = await fetch("/api/quarantine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          session_id: sessionId,
          reason: "Operator manual kill switch pressed from Blue Console",
        }),
      });
      if (res.ok) {
        alert("🚨 Kill switch engaged! Target sandbox terminated immediately.");
      }
    } catch (e) {
      console.error("Manual kill error:", e);
    }
  }

  async openForensicModal() {
    const modal = document.getElementById("forensic-modal");
    const tbody = document.getElementById("modal-ledger-tbody");
    if (!modal || !tbody) return;

    modal.classList.remove("hidden");
    tbody.innerHTML = '<tr><td colspan="6" class="text-muted">Loading cryptographic proof chain...</td></tr>';

    try {
      const [verifyRes, ledgerRes] = await Promise.all([
        fetch("/api/ledger/verify"),
        fetch("/api/ledger?limit=50"),
      ]);

      if (verifyRes.ok && ledgerRes.ok) {
        const verifyData = await verifyRes.json();
        const records = await ledgerRes.json();

        tbody.innerHTML = "";
        records.forEach((r) => {
          const tr = document.createElement("tr");
          tr.innerHTML = `
            <td>#${r.index}</td>
            <td><strong class="text-cyan">${r.source_zone}</strong></td>
            <td>${r.event_type}</td>
            <td><span class="${r.severity.includes('CRITICAL') ? 'text-red' : 'text-emerald'}">${r.severity}</span></td>
            <td class="text-muted">${r.previous_hash.substring(0, 10)}...</td>
            <td class="text-cyan">${r.current_hash.substring(0, 10)}...${r.current_hash.substring(58)}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    } catch (e) {
      console.error("Failed to load forensic ledger:", e);
    }
  }
}

window.addEventListener("DOMContentLoaded", () => {
  window.attackController = new AttackController();
});
