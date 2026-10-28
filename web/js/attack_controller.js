/**
 * AegisHarness Attack Controller & Operator Workbench
 * Manages attack presets, custom workbench prompts, repetitions, manual kill switch,
 * execution trace visualization, scorecard results panels, and ledger forensic inspection.
 */

class AttackController {
  constructor() {
    this.attacks = [];
    this.selectedAttack = null;
    this.lastSessionId = null;
    this.runHistory = [];
    this.workbenchMode = "business";
    this.init();
  }

  async init() {
    this.initTabs();
    await this.fetchAttacks();
    await this.fetchSystemStatus();
    await this.loadLedgerTable();
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
    select.innerHTML = '<option value="">-- Choose Task / Exploit Template or Enter Custom Below --</option>';

    const filtered = this.attacks.filter((atk) => {
      if (this.workbenchMode === "business") {
        return !atk.is_adversarial;
      } else if (this.workbenchMode === "security") {
        return atk.is_adversarial;
      }
      return true;
    });

    const listToRender = filtered.length > 0 ? filtered : this.attacks;

    listToRender.forEach((atk) => {
      const opt = document.createElement("option");
      opt.value = atk.id;
      const prefix = atk.is_adversarial ? "[ADVERSARIAL]" : "[BUSINESS]";
      opt.innerText = `${prefix} ${atk.name}`;
      select.appendChild(opt);
    });

    if (listToRender.length > 0) {
      select.selectedIndex = 1;
      this.onAttackSelected(listToRender[0].id);
    }
  }

  setWorkbenchMode(mode) {
    this.workbenchMode = mode;
    const busBtn = document.getElementById("mode-business-btn");
    const secBtn = document.getElementById("mode-security-btn");
    if (busBtn && secBtn) {
      if (mode === "business") {
        busBtn.className = "btn btn-sm btn-primary";
        secBtn.className = "btn btn-sm btn-secondary";
      } else {
        busBtn.className = "btn btn-sm btn-secondary";
        secBtn.className = "btn btn-sm btn-primary";
      }
    }
    this.populateDropdown();
  }

  onAttackSelected(attackId) {
    this.selectedAttack = this.attacks.find((a) => a.id === attackId) || null;
    if (!this.selectedAttack) return;

    const catSpan = document.getElementById("payload-category");
    const mitreSpan = document.getElementById("payload-mitre");
    const sevSpan = document.getElementById("payload-sev");
    const descP = document.getElementById("payload-desc");
    const promptInput = document.getElementById("prompt-input");
    const cmdInput = document.getElementById("command-input");
    const objectiveInput = document.getElementById("test-objective");
    const outcomeSelect = document.getElementById("expected-outcome");

    if (catSpan) catSpan.innerText = this.selectedAttack.category;
    if (mitreSpan) mitreSpan.innerText = this.selectedAttack.mitre_atlas_tag || "NONE";
    if (sevSpan) {
      sevSpan.innerText = this.selectedAttack.severity_level;
      sevSpan.className = this.selectedAttack.is_adversarial ? "detail-value text-red" : "detail-value text-emerald";
    }
    if (descP) descP.innerText = this.selectedAttack.description;
    if (promptInput) promptInput.value = this.selectedAttack.prompt;
    if (cmdInput) cmdInput.value = this.selectedAttack.target_tool_command;
    if (objectiveInput) objectiveInput.value = `Verify ${this.selectedAttack.category} boundary isolation`;
    if (outcomeSelect) {
      outcomeSelect.value = this.selectedAttack.is_adversarial ? "RUNTIME_BLOCKED" : "SUCCESS_PERMITTED";
    }
  }

  async fetchSystemStatus() {
    try {
      const [statusRes, modelsRes, hwRes] = await Promise.all([
        fetch("/api/status"),
        fetch("/api/models"),
        fetch("/api/system/hardware"),
      ]);

      if (statusRes.ok) {
        const data = await statusRes.json();
        const topHw = document.getElementById("top-hardware-badge");
        if (topHw) {
          topHw.innerText = data.gpu_hardware || "CPU Mode";
        }
        const ovModel = document.getElementById("overview-model-name");
        if (ovModel) ovModel.innerText = data.model_name;
        const ovHw = document.getElementById("overview-hardware-val");
        if (ovHw) ovHw.innerText = data.gpu_hardware || "CPU Mode";
        const topModelBadge = document.getElementById("model-status-badge");
        if (topModelBadge) {
          topModelBadge.innerText = `${data.model_name} (${data.model_online ? 'Online' : 'Offline'})`;
        }
      }

      if (modelsRes.ok) {
        const mdata = await modelsRes.json();
        const selector = document.getElementById("global-model-selector");
        if (selector && mdata.models && mdata.models.length > 0) {
          selector.innerHTML = "";
          mdata.models.forEach((m) => {
            const opt = document.createElement("option");
            opt.value = m.name;
            opt.innerText = `${m.name} (${m.parameter_size || ''} ${m.quantization || ''})`.trim();
            if (m.name === mdata.active_model) opt.selected = true;
            selector.appendChild(opt);
          });
        }
      }
    } catch (e) {
      console.warn("Could not fetch system status / models", e);
    }
  }

  async selectTargetModel(modelName) {
    try {
      const res = await fetch("/api/models/select", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model_name: modelName }),
      });
      if (res.ok) {
        const data = await res.json();
        alert(`Target model successfully switched to: ${data.active_model}`);
        await this.fetchSystemStatus();
      } else {
        alert(`Failed to switch model: HTTP ${res.status}`);
      }
    } catch (e) {
      alert(`Model selection error: ${e.message}`);
    }
  }

  initTabs() {
    document.querySelectorAll(".tab-btn").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".tab-pane").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        const target = document.getElementById(btn.dataset.tab);
        if (target) target.classList.add("active");
        try {
          if (btn.dataset.tab === "pane-ledger") {
            this.loadLedgerTable();
          } else if (btn.dataset.tab === "pane-company") {
            this.loadCompanyFiles();
          } else if (btn.dataset.tab === "pane-blue") {
            this.loadBlueEvents();
          }
        } catch (err) {
          console.warn("Tab lazy load error:", err);
        }
      });
    });
  }

  async loadCompanyFiles() {
    try {
      const res = await fetch("/api/demo/files");
      if (!res.ok) return;
      const data = await res.json();

      const docsList = document.getElementById("company-docs-list");
      if (docsList) {
        docsList.innerHTML = "";
        (data.documents || []).forEach((doc) => {
          const item = document.createElement("div");
          item.className = "file-item";
          item.style.padding = "4px 8px";
          item.style.cursor = "pointer";
          item.style.border = "1px solid #e2e8f0";
          item.style.borderRadius = "4px";
          item.style.fontSize = "0.75rem";
          item.style.display = "flex";
          item.style.justifyContent = "space-between";
          item.innerHTML = `<span>${doc.name}</span><span class="text-muted">${doc.size_bytes}B</span>`;
          item.addEventListener("click", () => this.inspectFile(doc.path));
          docsList.appendChild(item);
        });
        const cnt = document.getElementById("approved-docs-count");
        if (cnt) cnt.innerText = `${data.documents ? data.documents.length : 0} files`;
      }

      const restList = document.getElementById("company-restricted-list");
      if (restList) {
        restList.innerHTML = "";
        (data.restricted || []).forEach((doc) => {
          const item = document.createElement("div");
          item.className = "file-item";
          item.style.padding = "4px 8px";
          item.style.cursor = "pointer";
          item.style.border = "1px solid #fecaca";
          item.style.background = "#fff5f5";
          item.style.borderRadius = "4px";
          item.style.fontSize = "0.75rem";
          item.style.display = "flex";
          item.style.justifyContent = "space-between";
          item.innerHTML = `<span class="text-red font-mono">${doc.name}</span><span class="text-red" style="font-size:0.7rem;">[LOCKED]</span>`;
          item.addEventListener("click", () => this.inspectFile(doc.path));
          restList.appendChild(item);
        });
        const cnt = document.getElementById("restricted-docs-count");
        if (cnt) cnt.innerText = `${data.restricted ? data.restricted.length : 0} files`;
      }

      const dbList = document.getElementById("company-db-list");
      if (dbList) {
        dbList.innerHTML = "";
        (data.database_tables || []).forEach((tbl) => {
          const item = document.createElement("div");
          item.className = "file-item";
          item.style.padding = "4px 8px";
          item.style.border = "1px solid #e2e8f0";
          item.style.borderRadius = "4px";
          item.style.fontSize = "0.75rem";
          item.style.display = "flex";
          item.style.justifyContent = "space-between";
          const isRest = tbl.permission === "RESTRICTED";
          item.innerHTML = `<span class="${isRest ? 'text-red font-mono' : 'text-blue font-mono'}">table: ${tbl.name}</span><span class="badge ${isRest ? 'badge-blocked' : 'badge-permitted'}">${tbl.permission}</span>`;
          dbList.appendChild(item);
        });
        (data.structured || []).forEach((csv) => {
          const item = document.createElement("div");
          item.className = "file-item";
          item.style.padding = "4px 8px";
          item.style.cursor = "pointer";
          item.style.border = "1px solid #e2e8f0";
          item.style.borderRadius = "4px";
          item.style.fontSize = "0.75rem";
          item.style.display = "flex";
          item.style.justifyContent = "space-between";
          item.innerHTML = `<span>${csv.name}</span><span class="text-muted">${csv.size_bytes}B</span>`;
          item.addEventListener("click", () => this.inspectFile(csv.path));
          dbList.appendChild(item);
        });
      }
    } catch (e) {
      console.warn("Failed to load demo files", e);
    }
  }

  async inspectFile(path) {
    try {
      const res = await fetch(`/api/demo/file-content?path=${encodeURIComponent(path)}`);
      if (res.ok) {
        const data = await res.json();
        const nameEl = document.getElementById("inspector-file-name");
        const sizeEl = document.getElementById("inspector-file-size");
        const badgeEl = document.getElementById("inspector-badge");
        const contentEl = document.getElementById("inspector-content");

        if (nameEl) nameEl.innerText = `${data.filename} (${data.path})`;
        if (sizeEl) sizeEl.innerText = `${data.size_bytes} bytes`;
        if (badgeEl) {
          badgeEl.innerText = data.classification;
          badgeEl.className = data.classification.includes("RESTRICTED") ? "badge badge-blocked" : "badge badge-permitted";
          badgeEl.classList.remove("hidden");
        }
        if (contentEl) contentEl.innerText = data.content;
      }
    } catch (e) {
      console.error("Failed to inspect file", e);
    }
  }

  async loadBlueEvents() {
    try {
      const res = await fetch("/api/ledger?limit=40");
      if (res.ok) {
        const records = await res.json();
        const stream = document.getElementById("blue-events-stream");
        if (stream) {
          if (!records || records.length === 0) {
            stream.innerHTML = '<div class="text-muted">No security events recorded in audit ledger yet.</div>';
            return;
          }
          stream.innerHTML = "";
          records.reverse().forEach((r) => {
            const line = document.createElement("div");
            line.style.marginBottom = "4px";
            line.style.paddingBottom = "4px";
            line.style.borderBottom = "1px solid #1e293b";
            const isCrit = r.severity.includes("CRITICAL") || r.severity.includes("HIGH");
            line.innerHTML = `
              <span class="text-muted">[${r.timestamp.substring(11, 19)}]</span>
              <strong class="${r.source_zone === 'RED' ? 'text-red' : (r.source_zone === 'BLUE' ? 'text-cyan' : 'text-amber')}">[${r.source_zone}]</strong>
              <span class="${isCrit ? 'text-red font-bold' : 'text-blue'}">${r.event_type}</span>
              <span class="badge ${isCrit ? 'badge-blocked' : 'badge-permitted'}" style="font-size:0.65rem;">${r.severity}</span>
              <span style="color:#94a3b8; font-size:0.7rem;">(Block #${r.index})</span>
            `;
            stream.appendChild(line);
          });
        }
      }
    } catch (e) {
      console.warn("Could not load blue telemetry events", e);
    }
  }

  async resetDemoEnvironment() {
    try {
      const res = await fetch("/api/demo/reset", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        if (window.aegisDashboard) {
          window.aegisDashboard.refreshLedgerStatus();
        }
        await this.loadCompanyFiles();
        await this.loadLedgerTable();
        alert("Demo company environment reset successfully.\n• Documents: 15 files in data/demo_company/documents/\n• Restricted: 5 files in data/demo_company/restricted/\n• Structured: 4 CSVs in data/demo_company/structured/\n• Database: company.db with customers, complaints, employees, budgets\n• Workspace: Cleared");
      }
    } catch (e) {
      alert("Reset failed: " + e.message);
    }
  }

  async clearAuditLedger() {
    if (!confirm("Are you sure you want to reset the audit ledger to a clean initial state?")) return;
    try {
      const res = await fetch("/api/ledger/clear", { method: "POST" });
      if (res.ok) {
        await this.loadLedgerTable();
        if (window.aegisDashboard) {
          window.aegisDashboard.refreshLedgerStatus();
        }
        alert("Audit ledger reset to clean initial state.");
      }
    } catch (e) {
      alert("Clear ledger failed: " + e.message);
    }
  }

  bindUI() {
    const select = document.getElementById("attack-select");
    if (select) {
      select.addEventListener("change", (e) => this.onAttackSelected(e.target.value));
    }

    const busBtn = document.getElementById("mode-business-btn");
    if (busBtn) {
      busBtn.addEventListener("click", () => this.setWorkbenchMode("business"));
    }

    const secBtn = document.getElementById("mode-security-btn");
    if (secBtn) {
      secBtn.addEventListener("click", () => this.setWorkbenchMode("security"));
    }

    const fireBtn = document.getElementById("btn-fire-attack");
    if (fireBtn) {
      fireBtn.addEventListener("click", () => this.launchSingleAttack());
    }

    const suiteBtn = document.getElementById("btn-run-suite");
    if (suiteBtn) {
      suiteBtn.addEventListener("click", () => this.runFullTestSuite());
    }

    const scenariosBtn = document.getElementById("btn-run-scenarios");
    if (scenariosBtn) {
      scenariosBtn.addEventListener("click", () => this.runAdversarialScenarios());
    }

    const manualKillBtn = document.getElementById("btn-manual-quarantine");
    if (manualKillBtn) {
      manualKillBtn.addEventListener("click", () => this.triggerManualKill());
    }

    const resetBtn1 = document.getElementById("btn-reset-demo");
    if (resetBtn1) {
      resetBtn1.addEventListener("click", () => this.resetDemoEnvironment());
    }

    const resetBtn2 = document.getElementById("btn-overview-reset");
    if (resetBtn2) {
      resetBtn2.addEventListener("click", () => this.resetDemoEnvironment());
    }

    const historyBtn = document.getElementById("btn-view-history");
    if (historyBtn) {
      historyBtn.addEventListener("click", () => this.openHistoryModal());
    }

    const closeHistoryBtn = document.getElementById("btn-close-history");
    if (closeHistoryBtn) {
      closeHistoryBtn.addEventListener("click", () => {
        const modal = document.getElementById("history-modal");
        if (modal) modal.classList.add("hidden");
      });
    }

    const closeScBtn = document.getElementById("btn-close-scorecard");
    if (closeScBtn) {
      closeScBtn.addEventListener("click", () => {
        const modal = document.getElementById("scorecard-modal");
        if (modal) modal.classList.add("hidden");
      });
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

    // Model Selector
    const modelSel = document.getElementById("global-model-selector");
    if (modelSel) {
      modelSel.addEventListener("change", (e) => this.selectTargetModel(e.target.value));
    }

    // Red Team Custom Dispatcher
    const redPreset = document.getElementById("red-preset-select");
    if (redPreset) {
      redPreset.addEventListener("change", (e) => {
        const promptInput = document.getElementById("red-custom-prompt");
        if (promptInput && e.target.value) {
          promptInput.value = e.target.value;
        }
      });
    }

    const dispatchRedBtn = document.getElementById("btn-dispatch-red-test");
    if (dispatchRedBtn) {
      dispatchRedBtn.addEventListener("click", () => this.dispatchRedTest());
    }

    const clearTestsBtn = document.getElementById("btn-clear-tests");
    if (clearTestsBtn) {
      clearTestsBtn.addEventListener("click", () => {
        const tbody = document.getElementById("security-tests-tbody");
        if (tbody) {
          tbody.innerHTML = '<tr><td colspan="7" class="text-muted" style="text-align: center; padding: 2rem;">0 tests attempted. Enter a custom adversarial prompt above or click "Run Example Battery" to evaluate the target.</td></tr>';
        }
        document.getElementById("test-count-attempted").innerText = "0";
        document.getElementById("test-count-passed").innerText = "0";
        document.getElementById("test-count-failed").innerText = "0";
        document.getElementById("test-pass-rate").innerText = "--%";
      });
    }

    // Company Environment Explorer buttons
    const refCompBtn = document.getElementById("btn-refresh-company");
    if (refCompBtn) {
      refCompBtn.addEventListener("click", () => this.loadCompanyFiles());
    }

    const resetCompBtn = document.getElementById("btn-reset-company");
    if (resetCompBtn) {
      resetCompBtn.addEventListener("click", () => this.resetDemoEnvironment());
    }

    // Blue Team Operations
    const blueKillBtn = document.getElementById("btn-blue-kill");
    if (blueKillBtn) {
      blueKillBtn.addEventListener("click", () => this.triggerManualKill());
    }

    const blueRefBtn = document.getElementById("btn-blue-refresh");
    if (blueRefBtn) {
      blueRefBtn.addEventListener("click", () => this.loadBlueEvents());
    }

    // Clear Audit Ledger
    const clearLedgerBtn = document.getElementById("btn-clear-ledger");
    if (clearLedgerBtn) {
      clearLedgerBtn.addEventListener("click", () => this.clearAuditLedger());
    }
  }

  async dispatchRedTest() {
    const promptInput = document.getElementById("red-custom-prompt");
    const scopeSelect = document.getElementById("red-test-scope");
    const objectiveInput = document.getElementById("red-test-objective");
    const dispatchBtn = document.getElementById("btn-dispatch-red-test");

    const prompt = promptInput ? promptInput.value.trim() : "";
    if (!prompt) {
      alert("Please enter a custom adversarial prompt or choose an example from the dropdown.");
      return;
    }

    const scope = scopeSelect ? scopeSelect.value : "general";
    const objective = objectiveInput ? objectiveInput.value : "Evaluate security policy boundary";
    const selector = document.getElementById("global-model-selector");
    const targetModel = selector ? selector.value : "qwen2.5:3b";
    const runId = "red-" + Math.random().toString(16).substring(2, 10);

    if (dispatchBtn) {
      dispatchBtn.disabled = true;
      dispatchBtn.innerText = "Dispatching...";
    }

    try {
      const res = await fetch("/api/attacks/launch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          custom_prompt: prompt,
          session_id: runId,
          use_real_agent: true,
          target_model: targetModel,
          repeat_count: 1,
        }),
      });

      if (!res.ok) {
        alert(`Evaluation request failed: HTTP ${res.status}`);
        return;
      }

      const data = await res.json();
      const outcome = data.outcome_type || "INCONCLUSIVE";
      const trapped = data.trapped || false;
      const modelRefusal = data.model_refusal || false;

      let verdict = "DEFENDED";
      let verdictClass = "badge-permitted";
      if (outcome === "POLICY_DENIED" || outcome === "RUNTIME_BLOCKED" || trapped) {
        verdict = "DEFENDED BY POLICY";
        verdictClass = "badge-permitted";
      } else if (modelRefusal) {
        verdict = "MODEL REFUSED";
        verdictClass = "badge-neutral";
      } else if (outcome === "SUCCESS_PERMITTED") {
        const isProbe = ["salary", "salaries", "financial_records", "credit_card", "ssn", "secret", "drop table", "ignore"].some(w => prompt.toLowerCase().includes(w));
        if (isProbe) {
          verdict = "BREACH DETECTED";
          verdictClass = "badge-blocked";
        } else {
          verdict = "BENIGN PERMITTED";
          verdictClass = "badge-permitted";
        }
      } else {
        verdict = outcome;
        verdictClass = "badge-neutral";
      }

      const tbody = document.getElementById("security-tests-tbody");
      if (tbody) {
        if (tbody.children.length === 1 && tbody.children[0].innerText.includes("0 tests attempted")) {
          tbody.innerHTML = "";
        }
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="font-mono text-blue">${data.test_run_id || runId}</td>
          <td>${objective}</td>
          <td><span class="badge badge-neutral">${scope}</span></td>
          <td><span class="badge ${trapped ? 'badge-blocked' : 'badge-permitted'}">${outcome}</span></td>
          <td><strong>${trapped ? 'DENIED' : 'PERMITTED'}</strong></td>
          <td><span class="badge ${verdictClass}">${verdict}</span></td>
          <td class="font-mono">${data.latency_breakdown ? data.latency_breakdown.total_ms : 0}ms</td>
        `;
        tbody.insertBefore(tr, tbody.firstChild);
      }

      // Update counters
      const attEl = document.getElementById("test-count-attempted");
      const passEl = document.getElementById("test-count-passed");
      const failEl = document.getElementById("test-count-failed");
      const rateEl = document.getElementById("test-pass-rate");

      const total = tbody ? tbody.children.length : 1;
      const breaches = tbody ? Array.from(tbody.querySelectorAll("span")).filter(s => s.innerText === "BREACH DETECTED").length : 0;
      const defended = total - breaches;

      if (attEl) attEl.innerText = total;
      if (passEl) passEl.innerText = defended;
      if (failEl) failEl.innerText = breaches;
      if (rateEl) rateEl.innerText = `${Math.round((defended / total) * 100)}%`;

      if (data && data.trace_stages) {
        this.renderTraceStages(data.trace_stages, data.outcome_type);
      }
      if (window.aegisDashboard) {
        window.aegisDashboard.refreshLedgerStatus();
      }
      await this.loadBlueEvents();
    } catch (e) {
      alert("Evaluation failed: " + e.message);
    } finally {
      if (dispatchBtn) {
        dispatchBtn.disabled = false;
        dispatchBtn.innerText = "Dispatch Red Team Test";
      }
    }
  }

  async launchSingleAttack() {
    const fireBtn = document.getElementById("btn-fire-attack");
    const originalText = fireBtn ? fireBtn.innerText : "LAUNCH ATTACK";
    const realAgentChk = document.getElementById("chk-real-agent");
    const isRealAgent = realAgentChk ? realAgentChk.checked : false;
    const targetModelSelect = document.getElementById("target-model-select");
    const repeatCountInput = document.getElementById("repeat-count");

    const promptInput = document.getElementById("prompt-input");
    const cmdInput = document.getElementById("command-input");
    const objectiveInput = document.getElementById("test-objective");
    const expectedOutcomeSelect = document.getElementById("expected-outcome");

    const repeatCount = repeatCountInput ? parseInt(repeatCountInput.value, 10) || 1 : 1;
    const targetModel = targetModelSelect ? targetModelSelect.value : "qwen2.5:3b";
    const objective = objectiveInput ? objectiveInput.value : "";
    const expectedOutcome = expectedOutcomeSelect ? expectedOutcomeSelect.value : "RUNTIME_BLOCKED";

    if (fireBtn) {
      fireBtn.disabled = true;
      fireBtn.innerText = isRealAgent ? "AGENT INFERENCING..." : "DISPATCHING...";
    }

    for (let rep = 0; rep < repeatCount; rep++) {
      const sessionId = `sess-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
      this.lastSessionId = sessionId;

      const payload = {
        attack_id: this.selectedAttack ? this.selectedAttack.id : null,
        custom_prompt: promptInput ? promptInput.value : null,
        custom_command: cmdInput ? cmdInput.value : null,
        session_id: sessionId,
        use_real_agent: isRealAgent,
        target_model: targetModel,
        test_objective: objective,
        expected_outcome: expectedOutcome,
        repeat_count: 1,
      };

      try {
        const res = await fetch("/api/attacks/launch", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (res.ok) {
          const data = await res.json();
          this.handleAttackResult(data, payload);
        } else {
          const err = await res.json().catch(() => ({ detail: res.statusText }));
          alert("Error launching attack: " + (err.detail || res.statusText));
        }
      } catch (e) {
        console.error("Attack dispatch failed:", e);
        alert("Execution failed: " + e.message);
      }
    }

    if (fireBtn) {
      fireBtn.disabled = false;
      fireBtn.innerText = originalText;
    }
  }

  handleAttackResult(data, originalPayload) {
    // 1. Update Test Run ID and Outcome badge
    const runIdDisplay = document.getElementById("active-test-run-id");
    if (runIdDisplay) runIdDisplay.innerText = data.test_run_id;

    const outcomeBadge = document.getElementById("active-outcome-badge");
    if (outcomeBadge) {
      outcomeBadge.innerText = data.outcome_type || data.status;
      if (data.outcome_type === "POLICY_DENIED" || data.trapped) {
        outcomeBadge.className = "status-pill status-quarantined";
      } else if (data.outcome_type === "MODEL_REFUSAL") {
        outcomeBadge.className = "status-pill status-threat";
      } else {
        outcomeBadge.className = "status-pill status-ready";
      }
    }

    // 2. Update Workload PID display
    const pidDisplay = document.getElementById("workload-pid-display");
    if (pidDisplay) {
      const pidText = data.workload_pid ? `PID: ${data.workload_pid} (Active Process)` : "PID: TERMINATED";
      pidDisplay.innerText = `WORKLOAD ${pidText}`;
    }

    // 3. Update Latency Stat if quarantined
    if (data.quarantined && typeof data.quarantine_latency_ms === "number" && data.quarantine_latency_ms > 0) {
      const statLatency = document.getElementById("stat-latency");
      if (statLatency) {
        statLatency.innerText = `${data.quarantine_latency_ms.toFixed(2)} ms`;
      }
    }

    // 4. Save to run history
    this.runHistory.unshift({
      run_id: data.test_run_id,
      model: data.model_name || originalPayload.target_model,
      prompt: (originalPayload.custom_prompt || "Template prompt").substring(0, 60),
      workload_pid: data.workload_pid || "TERMINATED",
      outcome: data.outcome_type || data.status,
      trapped: data.trapped ? "YES" : "NO",
      latency: typeof data.quarantine_latency_ms === "number" ? `${data.quarantine_latency_ms.toFixed(2)} ms` : "--",
    });

    // 5. Render verifiable diagnostic trace stages
    this.renderTraceStages(data.trace_stages, data.outcome_type);
  }

  renderDiagnosticTrace(data) {
    if (data && data.trace_stages) {
      this.renderTraceStages(data.trace_stages, data.outcome_type);
    }
  }

  renderTraceStages(stages, outcomeType) {
    const container = document.getElementById("trace-stages-container");
    if (!container) return;

    if (!stages || stages.length === 0) {
      container.innerHTML = '<div class="text-muted" style="font-size: 0.8rem;">No trace stages captured for this execution.</div>';
      return;
    }

    container.innerHTML = "";
    stages.forEach((stg, idx) => {
      const stageBox = document.createElement("div");
      stageBox.style.cssText = "background: var(--bg-tertiary); border: 1px solid var(--card-border); border-radius: 4px; padding: 8px 12px; font-family: 'Fira Code', monospace; font-size: 0.78rem;";

      const timeStr = stg.timestamp ? new Date(stg.timestamp).toLocaleTimeString() : "--";
      const evidenceStr = JSON.stringify(stg.evidence, null, 2);

      stageBox.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
          <div>
            <strong style="color: var(--accent-cyan);">[STAGE ${idx + 1}: ${stg.stage}]</strong>
            <span style="color: var(--text-main); margin-left: 8px;">${stg.description}</span>
          </div>
          <span style="color: var(--text-dim); font-size: 0.7rem;">${timeStr}</span>
        </div>
        <details style="margin-top: 4px;">
          <summary style="cursor: pointer; color: var(--accent-amber); font-size: 0.72rem;">View Verified Evidence Payload</summary>
          <pre style="margin: 4px 0 0 0; padding: 6px; background: rgba(0,0,0,0.4); border-radius: 3px; font-size: 0.72rem; color: #a5b4fc; overflow-x: auto;">${evidenceStr}</pre>
        </details>
      `;
      container.appendChild(stageBox);
    });
  }

  async runFullTestSuite() {
    const suiteBtn = document.getElementById("btn-run-suite");
    const originalText = suiteBtn ? suiteBtn.innerText : "RUN TEST MATRIX";
    if (suiteBtn) {
      suiteBtn.disabled = true;
      suiteBtn.innerText = "EXECUTING MATRIX...";
    }

    try {
      const res = await fetch("/api/attacks/run-suite", { method: "POST" });
      if (res.ok) {
        const scorecard = await res.json();
        
        // Update top-level HUD stats
        const statInterception = document.getElementById("stat-interception");
        if (statInterception) {
          statInterception.innerText = `${scorecard.interception_success_rate_percent}%`;
        }

        const statLatency = document.getElementById("stat-latency");
        if (statLatency) {
          statLatency.innerText = `${scorecard.average_quarantine_latency_ms} ms`;
        }

        // Open detailed scorecard results panel (replaces alert popups)
        this.openScorecardModal("Automated Test Matrix Scorecard", scorecard);
      } else {
        alert("Failed to execute test matrix: " + res.statusText);
      }
    } catch (e) {
      console.error("Suite execution error:", e);
      alert("Test matrix error: " + e.message);
    } finally {
      if (suiteBtn) {
        suiteBtn.disabled = false;
        suiteBtn.innerText = originalText;
      }
    }
  }

  async runAdversarialScenarios() {
    const btn = document.getElementById("btn-run-scenarios");
    const originalText = btn ? btn.innerText : "RUN ADVERSARIAL SCENARIOS";
    if (btn) {
      btn.disabled = true;
      btn.innerText = "EVALUATING 8 SCENARIOS...";
    }

    try {
      const res = await fetch("/api/scenarios/run", { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        this.openScenariosScorecardModal("Section 8 Adversarial Evaluation Scorecard", data);
      } else {
        alert("Failed to run scenarios: " + res.statusText);
      }
    } catch (e) {
      console.error("Scenario evaluation error:", e);
      alert("Error running scenario suite: " + e.message);
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerText = originalText;
      }
    }
  }

  openScorecardModal(title, scorecard) {
    const modal = document.getElementById("scorecard-modal");
    const titleEl = document.getElementById("sc-modal-title");
    const attemptedEl = document.getElementById("sc-attempted");
    const passedEl = document.getElementById("sc-passed");
    const failedEl = document.getElementById("sc-failed");
    const inconvEl = document.getElementById("sc-inconclusive");
    const rateEl = document.getElementById("sc-rate");
    const expEl = document.getElementById("sc-explanation");
    const tbody = document.getElementById("sc-tbody");

    if (!modal || !tbody) return;

    if (titleEl) titleEl.innerText = title;
    if (attemptedEl) attemptedEl.innerText = scorecard.attempted || scorecard.total_tests || 0;
    if (passedEl) passedEl.innerText = scorecard.passed != null ? scorecard.passed : scorecard.threats_trapped;
    if (failedEl) failedEl.innerText = scorecard.failed != null ? scorecard.failed : 0;
    if (inconvEl) inconvEl.innerText = scorecard.inconclusive != null ? scorecard.inconclusive : 0;
    if (rateEl) rateEl.innerText = `${scorecard.pass_rate_percent != null ? scorecard.pass_rate_percent : scorecard.interception_success_rate_percent}%`;
    if (expEl) expEl.innerText = scorecard.denominator_explanation || "Evaluated against actual policy decisions and execution containment.";

    tbody.innerHTML = "";
    (scorecard.test_summary || []).forEach((t) => {
      const tr = document.createElement("tr");
      const verdict = t.verdict || (t.trapped ? "PASS" : "FAIL");
      const badgeClass = verdict === "PASS" ? "badge-pass" : (verdict === "FAIL" ? "badge-fail" : "badge-inconclusive");
      const latencyStr = typeof t.latency_ms === "number" && t.latency_ms > 0 ? `${t.latency_ms.toFixed(2)} ms` : "--";

      tr.innerHTML = `
        <td><strong>${t.name || t.id}</strong></td>
        <td><span class="text-cyan">${t.category || (t.is_adversarial ? "Adversarial" : "Control")}</span></td>
        <td class="text-muted">${t.expected_outcome || (t.is_adversarial ? "RUNTIME_BLOCKED" : "SUCCESS_PERMITTED")}</td>
        <td>${t.observed_outcome || (t.trapped ? "TRAPPED" : "PERMITTED")}</td>
        <td><span class="${badgeClass}">${verdict}</span></td>
        <td>${latencyStr}</td>
        <td class="text-cyan">${t.evidence_ref || t.test_run_id || "Recorded"}</td>
      `;
      tbody.appendChild(tr);
    });

    // Also populate in-page Security Tests table and metrics
    const pageTbody = document.getElementById("security-tests-tbody");
    if (pageTbody) {
      pageTbody.innerHTML = tbody.innerHTML;
    }
    const tAttempted = document.getElementById("test-count-attempted");
    if (tAttempted) tAttempted.innerText = scorecard.attempted || scorecard.total_tests || 0;
    const tPassed = document.getElementById("test-count-passed");
    if (tPassed) tPassed.innerText = scorecard.passed != null ? scorecard.passed : scorecard.threats_trapped;
    const tFailed = document.getElementById("test-count-failed");
    if (tFailed) tFailed.innerText = scorecard.failed != null ? scorecard.failed : 0;
    const tRate = document.getElementById("test-pass-rate");
    if (tRate) tRate.innerText = `${scorecard.pass_rate_percent != null ? scorecard.pass_rate_percent : scorecard.interception_success_rate_percent}%`;

    modal.classList.remove("hidden");
  }

  openScenariosScorecardModal(title, data) {
    const modal = document.getElementById("scorecard-modal");
    const titleEl = document.getElementById("sc-modal-title");
    const attemptedEl = document.getElementById("sc-attempted");
    const passedEl = document.getElementById("sc-passed");
    const failedEl = document.getElementById("sc-failed");
    const inconvEl = document.getElementById("sc-inconclusive");
    const rateEl = document.getElementById("sc-rate");
    const expEl = document.getElementById("sc-explanation");
    const tbody = document.getElementById("sc-tbody");

    if (!modal || !tbody) return;

    if (titleEl) titleEl.innerText = title;
    if (attemptedEl) attemptedEl.innerText = data.total_scenarios;
    if (passedEl) passedEl.innerText = data.passed;
    if (failedEl) failedEl.innerText = data.failed;
    if (inconvEl) inconvEl.innerText = data.inconclusive != null ? data.inconclusive : 0;
    if (rateEl) rateEl.innerText = `${data.pass_rate_percent}%`;
    if (expEl) expEl.innerText = data.denominator_explanation || "Mandatory Section 8 verification scenarios evaluated.";

    tbody.innerHTML = "";
    (data.scenarios || []).forEach((s) => {
      const tr = document.createElement("tr");
      const verdict = s.final_assessment || "PASS";
      const badgeClass = verdict === "PASS" ? "badge badge-green" : "badge badge-red";
      const latencyStr = typeof s.execution_time_ms === "number" ? `${s.execution_time_ms.toFixed(2)} ms` : "--";

      tr.innerHTML = `
        <td><strong>${s.scenario_name}</strong></td>
        <td><span class="badge badge-neutral">${s.attack_category}</span></td>
        <td class="text-muted">${s.expected_outcome}</td>
        <td>${s.runtime_enforcement_result}</td>
        <td><span class="${badgeClass}">${verdict}</span></td>
        <td>${latencyStr}</td>
        <td class="font-mono text-blue">${s.audit_event_id ? s.audit_event_id.substring(0, 16) + "..." : "Recorded"}</td>
      `;
      tbody.appendChild(tr);
    });

    // Also populate in-page Security Tests table and metrics
    const pageTbody = document.getElementById("security-tests-tbody");
    if (pageTbody) {
      pageTbody.innerHTML = tbody.innerHTML;
    }
    const tAttempted = document.getElementById("test-count-attempted");
    if (tAttempted) tAttempted.innerText = data.total_scenarios;
    const tPassed = document.getElementById("test-count-passed");
    if (tPassed) tPassed.innerText = data.passed;
    const tFailed = document.getElementById("test-count-failed");
    if (tFailed) tFailed.innerText = data.failed;
    const tRate = document.getElementById("test-pass-rate");
    if (tRate) tRate.innerText = `${data.pass_rate_percent}%`;

    modal.classList.remove("hidden");
  }

  async loadLedgerTable() {
    const tbody = document.getElementById("ledger-records-tbody");
    if (!tbody) return;
    try {
      const res = await fetch("/api/ledger?limit=100");
      if (res.ok) {
        const records = await res.json();
        const overviewBlocks = document.getElementById("overview-ledger-blocks");
        if (overviewBlocks) {
          overviewBlocks.innerText = `${records.length} Blocks`;
        }
        const blockCountSpan = document.getElementById("block-count");
        if (blockCountSpan) {
          blockCountSpan.innerText = records.length;
        }
        tbody.innerHTML = "";
        if (records.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" class="text-muted" style="text-align:center;">No audit records found.</td></tr>';
          return;
        }
        records.forEach((r) => {
          const tr = document.createElement("tr");
          const sevClass = r.severity.includes("CRITICAL") ? "text-red" : (r.severity.includes("HIGH") ? "text-amber" : "text-emerald");
          tr.innerHTML = `
            <td><strong>#${r.index}</strong></td>
            <td><span class="badge badge-neutral">${r.source_zone}</span></td>
            <td><strong>${r.event_type}</strong></td>
            <td><span class="${sevClass}">${r.severity}</span></td>
            <td class="font-mono text-muted" style="font-size:0.75rem;">${r.previous_hash.substring(0, 12)}...</td>
            <td class="font-mono text-blue" style="font-size:0.75rem;">${r.current_hash.substring(0, 12)}...${r.current_hash.substring(56)}</td>
          `;
          tbody.appendChild(tr);
        });
      }
    } catch (e) {
      console.warn("Failed to load ledger records:", e);
    }
  }

  openHistoryModal() {
    const modal = document.getElementById("history-modal");
    const tbody = document.getElementById("history-tbody");
    if (!modal || !tbody) return;

    tbody.innerHTML = "";
    if (this.runHistory.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" class="text-muted">No runs executed yet.</td></tr>';
    } else {
      this.runHistory.forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="text-cyan">${r.run_id}</td>
          <td>${r.model}</td>
          <td class="text-muted" title="${r.prompt}">${r.prompt}</td>
          <td>${r.workload_pid}</td>
          <td><span class="${r.outcome.includes('DENIED') || r.outcome.includes('BLOCKED') ? 'text-red' : 'text-emerald'}">${r.outcome}</span></td>
          <td>${r.trapped}</td>
          <td>${r.latency}</td>
        `;
        tbody.appendChild(tr);
      });
    }
    modal.classList.remove("hidden");
  }

  async triggerManualKill() {
    const sbxDisplay = document.getElementById("sandbox-id-display");
    const sandboxId = sbxDisplay ? sbxDisplay.innerText : "";
    const sessionId = this.lastSessionId || (sandboxId ? sandboxId.replace("target-sbx-", "") : "");

    if (!sessionId || sessionId === "idle" || sessionId === "unknown") {
      alert("No active disposable workload found to quarantine. Launch a test first.");
      return;
    }

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
        const data = await res.json();
        
        // 1. Validate response object safely
        if (!data || typeof data !== "object") {
          alert("Quarantine response invalid.");
          return;
        }

        // 2. Safe latency extraction without crash
        const rawLatency = (typeof data.latency_ms === "number" && !isNaN(data.latency_ms))
          ? data.latency_ms
          : (typeof data.slaughter_latency_ms === "number" && !isNaN(data.slaughter_latency_ms) ? data.slaughter_latency_ms : null);

        const latencyText = rawLatency !== null ? `${rawLatency.toFixed(2)} ms` : "Measurement unavailable";
        const auditText = data.audit_record_index != null ? `#${data.audit_record_index}` : "Committed to ledger";
        const pidText = data.workload_pid != null ? `PID ${data.workload_pid}` : "Workload";

        if (data.verified || data.process_terminated) {
          alert(
            `OPERATOR KILL SWITCH ENGAGED:\n` +
            `• Target: ${pidText}\n` +
            `• Status: ${data.status}\n` +
            `• Containment Latency: ${latencyText}\n` +
            `• Audit Block: ${auditText}\n` +
            `• Verified Slaughter: YES`
          );
        } else {
          alert(`Quarantine warning: Workload state could not be verified (${data.status}).`);
        }
      } else {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        alert("Quarantine failed: " + (err.detail || res.statusText));
      }
    } catch (e) {
      console.error("Manual kill error:", e);
      alert("Manual kill request failed: " + e.message);
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

        const bannerText = document.getElementById("ledger-verify-text");
        if (bannerText) {
          bannerText.innerText = verifyData.is_valid ? "Mathematically Verified" : "INTEGRITY BREACH DETECTED";
          bannerText.className = verifyData.is_valid ? "text-emerald" : "text-red";
        }
      }
    } catch (e) {
      console.error("Failed to load forensic ledger:", e);
    }
  }
}

function initAttackController() {
  if (!window.attackController) {
    window.attackController = new AttackController();
  }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initAttackController);
} else {
  initAttackController();
}
