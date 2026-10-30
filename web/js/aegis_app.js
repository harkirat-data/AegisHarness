/**
 * AegisHarness Frontend App
 * Connects Red Team, Target Sandbox, and Blue Team views to the real API.
 */

// ===== STATE =====
const state = {
  currentTab: 'red-team',
  activeMode: 'company',
  activeModel: 'qwen2.5:3b',
  sessionId: `ui-${Date.now()}`,
  chatHistory: [],
  allEvents: [],
  eventsFilter: 'all',
  stats: { total: 0, threats: 0, blocked: 0, permitted: 0, ledgerBlocks: 0, integrity: null },
  ws: null,
  wsRetries: 0,
  isQuarantined: false,
};

// ===== TAB NAVIGATION =====
function switchTab(tab, btn) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const target = document.getElementById(`pane-${tab}`) || document.getElementById(`tab-${tab}`);
  if (target) target.classList.add('active');
  if (btn) btn.classList.add('active');
  state.currentTab = tab;

  if (tab === 'sandbox' || tab === 'target') {
    loadSandboxFiles();
  }
  if (tab === 'blue-team' || tab === 'blue') {
    loadLedger();
    refreshStats();
  }
}

// ===== AGENT MODE =====
function setMode(mode, btn) {
  state.activeMode = mode;
  document.querySelectorAll('.mode-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  const hint = document.getElementById('mode-hint');
  if (hint) {
    hint.textContent =
      mode === 'company' ? 'Company documents, policies, and records only' : 'General knowledge assistant mode';
  }
}

// ===== MODEL SELECT =====
document.addEventListener('DOMContentLoaded', () => {
  const sel = document.getElementById('model-select') || document.getElementById('global-model-selector');
  if (sel) {
    sel.addEventListener('change', function () {
      state.activeModel = this.value;
      const lbl = document.getElementById('active-model-label');
      if (lbl) lbl.textContent = this.value;
      updateModelChip();
    });
  }
});

// ===== WEBSOCKET =====
function connectWS() {
  const wsUrl = `ws://${location.host}/ws/telemetry`;
  const ws = new WebSocket(wsUrl);
  state.ws = ws;

  ws.onopen = () => {
    state.wsRetries = 0;
    setWsStatus(true);
    ws.send('ping');
  };

  ws.onmessage = evt => {
    try {
      const msg = JSON.parse(evt.data);
      handleWsEvent(msg);
    } catch { /* ignore malformed */ }
  };

  ws.onclose = () => {
    setWsStatus(false);
    if (state.wsRetries < 6) {
      state.wsRetries++;
      setTimeout(connectWS, 2000 * state.wsRetries);
    }
  };

  ws.onerror = () => ws.close();

  // keepalive ping
  const ka = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send('ping');
    else clearInterval(ka);
  }, 15000);
}

function handleWsEvent(msg) {
  const type = msg.type || '';
  const zone = msg.zone || '';
  const data = msg.data || {};

  // Append to exec log in red team if active
  const execMsg = buildExecEvent(type, zone, data);
  if (execMsg) appendExecEvent(execMsg);

  // Quarantine banner
  if (type === 'QUARANTINE_ACTION') {
    showQuarantineBanner(`Workload PID ${data.workload_pid} slaughtered in ${data.slaughter_latency_ms?.toFixed(1) || 0}ms (${data.reason || 'Critical security violation'})`);
    updateSandboxStateChips('QUARANTINED');
    state.stats.threats++;
    if (data.session_id === state.sessionId) {
      lockChatForQuarantine(data.slaughter_latency_ms, data.reason);
    }
  }

  if (type === 'ATTACK_RECEIVED') {
    updateSandboxStateChips('EXECUTING');
  }

  if (type === 'AGENT_INFERENCE_STARTING') {
    updateSandboxStateChips('EXECUTING');
  }

  if (type === 'SANDBOX_STATUS') {
    updateSandboxStateChips(data.state || 'IDLE');
  }

  refreshStats();
}

function buildExecEvent(type, zone, data) {
  const stageClass = {
    'ATTACK_RECEIVED': 'stage-warn',
    'AGENT_INFERENCE_STARTING': 'stage-info',
    'AGENT_RESPONSE_RECEIVED': 'stage-info',
    'TOOL_REQUEST_EVALUATED': 'stage-warn',
    'QUARANTINE_ACTION': 'stage-quarantine',
    'SYSCALL_TRAPPED': 'stage-denied',
    'CONNECTION_ESTABLISHED': 'stage-info',
  }[type] || 'stage-info';

  return { type, zone, data, stageClass, ts: new Date().toLocaleTimeString() };
}

function appendExecEvent(ev) {
  const log = document.getElementById('exec-log');
  const empty = log.querySelector('.exec-empty');
  if (empty) empty.remove();

  const row = document.createElement('div');
  row.className = `exec-event ${ev.stageClass}`;
  const desc = execEventDesc(ev.type, ev.data);
  row.innerHTML = `
    <span class="exec-stage">${ev.type}</span>
    <span class="exec-desc">${desc}</span>
    <span class="exec-ts">${ev.ts}</span>
  `;
  log.appendChild(row);
  log.scrollTop = log.scrollHeight;
}

function execEventDesc(type, data) {
  const esc = s => String(s || '').replace(/</g, '&lt;');
  switch (type) {
    case 'ATTACK_RECEIVED': return `Attack dispatched: <strong>${esc(data.attack_name)}</strong> [${esc(data.severity)}]`;
    case 'AGENT_INFERENCE_STARTING': return `Model <em>${esc(data.model)}</em> processing promptΓÇª`;
    case 'AGENT_RESPONSE_RECEIVED': return `Model responded. Refused: <strong>${data.refused}</strong>. Outcome: ${esc(data.outcome)}`;
    case 'TOOL_REQUEST_EVALUATED': return `Tool <code>${esc(data.tool)}</code> ΓåÆ Policy: <strong>${data.policy_approved ? 'APPROVED' : 'DENIED'}</strong>`;
    case 'QUARANTINE_ACTION': return `≡ƒöÆ <strong>QUARANTINE</strong>: PID ${data.workload_pid} terminated in ${data.slaughter_latency_ms?.toFixed(1) || 0}ms`;
    case 'SYSCALL_TRAPPED': return `Syscall intercepted: <code>${esc(data.syscall_name)}</code> ΓÇö ${esc(data.reason)}`;
    case 'SANDBOX_STATUS': return `Sandbox state ΓåÆ ${esc(data.state)}`;
    default: return esc(JSON.stringify(data).slice(0, 100));
  }
}

function setWsStatus(connected) {
  const dot = document.getElementById('ws-dot');
  const lbl = document.getElementById('ws-label');
  dot.className = `dot ${connected ? 'dot-pulse' : 'dot-gray'}`;
  lbl.textContent = connected ? 'Live' : 'ReconnectingΓÇª';
}

// ===== CHAT =====
function handleChatKey(evt) {
  if (evt.ctrlKey && evt.key === 'Enter') sendChat();
}

async function sendChat() {
  const input = document.getElementById('chat-input');
  const msg = input.value.trim();
  if (!msg) return;

  if (state.isQuarantined) {
    appendChatMsg('system', 'Workload is quarantined and terminated. Click "+ New Sandbox" above to launch a new session.', 'denied');
    return;
  }

  input.value = '';
  const btn = document.getElementById('send-btn');
  btn.disabled = true;
  btn.textContent = 'SendingΓÇª';

  // Append user message
  appendChatMsg('user', msg);

  // Show thinking
  const thinkingId = appendThinking();

  try {
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: msg,
        session_id: state.sessionId,
        target_model: state.activeModel,
        assistant_mode: state.activeMode,
      }),
    });

    removeThinking(thinkingId);

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      appendChatMsg('system', `Error: ${err.detail || res.statusText}`, 'error');
      if (res.status === 403) {
        lockChatForQuarantine(1.5, err.detail);
      }
      return;
    }

    const data = await res.json();
    const reply = data.final_response || data.message || 'No response.';
    const badge = outcomeToStatus(data.outcome_type, data.pep_authorized);

    appendChatMsg('agent', reply, badge, data.sources || []);

    // Update execution log with structured trace
    updateExecFromChatResponse(data);

    // Update stats
    state.stats.total++;
    if (data.pep_authorized === false) state.stats.blocked++;
    else state.stats.permitted++;
    if (data.outcome_type === 'POLICY_DENIED' || data.outcome_type === 'RUNTIME_BLOCKED') state.stats.threats++;
    refreshStats();

    // Check if auto-quarantine triggered on this response
    if (data.quarantined) {
      lockChatForQuarantine(data.quarantine_latency_ms, data.pep_reason || 'Policy violation detected');
    } else {
      updateSandboxStateChips('ACTIVE');
    }

  } catch (e) {
    removeThinking(thinkingId);
    appendChatMsg('system', `Network error: ${e.message}`, 'error');
  } finally {
    if (!state.isQuarantined) {
      btn.disabled = false;
      btn.textContent = 'Send Γû╢';
      input.focus();
    }
  }
}

function updateExecFromChatResponse(data) {
  const log = document.getElementById('exec-log');
  const empty = log.querySelector('.exec-empty');
  if (empty) empty.remove();

  const stages = data.trace_stages || [];

  if (stages.length === 0) {
    // Build synthetic stages from flat response
    const syntheticStages = buildSyntheticStages(data);
    syntheticStages.forEach(s => {
      const row = document.createElement('div');
      row.className = `exec-event ${s.cls}`;
      row.innerHTML = `<span class="exec-stage">${s.stage}</span><span class="exec-desc">${s.desc}</span><span class="exec-ts">${new Date().toLocaleTimeString()}</span>`;
      log.appendChild(row);
    });
  } else {
    stages.forEach(s => {
      const row = document.createElement('div');
      const cls = stageToClass(s.stage);
      row.className = `exec-event ${cls}`;
      row.innerHTML = `<span class="exec-stage">${s.stage}</span><span class="exec-desc">${s.description || ''}</span><span class="exec-ts">${new Date().toLocaleTimeString()}</span>`;
      log.appendChild(row);
    });
  }

  log.scrollTop = log.scrollHeight;

  // Update tool summary if a tool was called
  if (data.tool_name || data.tool_executed) {
    showToolSummary(data);
  }
}

function buildSyntheticStages(data) {
  const stages = [];
  stages.push({ stage: 'PROMPT_INGESTED', cls: 'stage-info', desc: `Mode: ${data.assistant_mode || 'company'} | Model: ${data.target_model}` });

  if (data.tool_proposal) {
    stages.push({ stage: 'TOOL_PROPOSED', cls: 'stage-warn', desc: `Tool: <code>${data.tool_name || data.tool_proposal?.tool}</code>` });
  }

  if (data.tool_status === 'SUCCESS' || data.pep_authorized === true) {
    stages.push({ stage: 'PEP_AUTHORIZED', cls: 'stage-ok', desc: `Policy APPROVED ΓÇö operation permitted` });
  } else if (data.pep_authorized === false) {
    stages.push({ stage: 'PEP_DENIED', cls: 'stage-denied', desc: `Policy DENIED ΓÇö ${data.pep_reason || 'access blocked by Zero-Trust PEP'}` });
  } else if (data.scope_status === 'REFUSED') {
    stages.push({ stage: 'MODEL_REFUSAL', cls: 'stage-warn', desc: 'Model safety guardrail activated before tool execution' });
  }

  if (data.audit_hash) {
    stages.push({ stage: 'LEDGER_WRITTEN', cls: 'stage-ok', desc: `Audit block hash: <code>${data.audit_hash.slice(0, 16)}ΓÇª</code>` });
  }

  return stages;
}

function stageToClass(stage) {
  if (stage.includes('DENIED') || stage.includes('TRAP') || stage.includes('QUARANTINE')) return 'stage-denied';
  if (stage.includes('AUTHORIZED') || stage.includes('SUCCESS') || stage.includes('LEDGER')) return 'stage-ok';
  if (stage.includes('WARN') || stage.includes('THREAT') || stage.includes('INGESTED')) return 'stage-warn';
  return 'stage-info';
}

function showToolSummary(data) {
  const summary = document.getElementById('tool-summary');
  const tbody = document.getElementById('tool-table-body');
  summary.classList.remove('hidden');
  tbody.innerHTML = `
    <tr><td>Tool</td><td>${esc(data.tool_name || data.tool_executed || 'ΓÇö')}</td></tr>
    <tr><td>Status</td><td>${esc(data.tool_status || 'ΓÇö')}</td></tr>
    <tr><td>Policy</td><td>${data.pep_authorized ? '<span class="text-green">AUTHORIZED</span>' : '<span class="text-red">DENIED</span>'}</td></tr>
    <tr><td>Outcome</td><td>${esc(data.outcome_type || 'ΓÇö')}</td></tr>
    <tr><td>Latency</td><td>${data.latency_ms || 'ΓÇö'}ms</td></tr>
    ${data.audit_hash ? `<tr><td>Audit Hash</td><td class="mono">${data.audit_hash.slice(0, 20)}ΓÇª</td></tr>` : ''}
  `;
}

function outcomeToStatus(outcomeType, pepAuthorized) {
  if (outcomeType === 'POLICY_DENIED' || outcomeType === 'RUNTIME_BLOCKED') return 'denied';
  if (outcomeType === 'MODEL_REFUSAL') return 'refused';
  if (pepAuthorized === false) return 'denied';
  if (outcomeType === 'EXECUTION_ERROR') return 'error';
  return 'ok';
}

function appendChatMsg(role, text, status, sources = []) {
  const log = document.getElementById('chat-log');
  const welcome = log.querySelector('.chat-welcome');
  if (welcome) welcome.remove();

  const div = document.createElement('div');
  div.className = `chat-msg ${role}`;

  const avatar = role === 'user' ? '≡ƒæñ' : role === 'system' ? 'ΓÜá∩╕Å' : '≡ƒñû';
  const avatarCls = role === 'user' ? 'avatar-user' : role === 'system' ? 'avatar-system' : 'avatar-agent';

  let badgeHtml = '';
  if (status && role !== 'user') {
    const badgeMap = { ok: 'badge-ok', denied: 'badge-denied', refused: 'badge-refused', info: 'badge-info', error: 'badge-error' };
    const badgeLbl = { ok: 'PERMITTED', denied: 'BLOCKED', refused: 'REFUSED', info: 'INFO', error: 'ERROR' };
    badgeHtml = `<span class="msg-badge ${badgeMap[status] || 'badge-info'}">${badgeLbl[status] || status.toUpperCase()}</span>`;
  }

  let sourcesHtml = '';
  if (sources.length) {
    sourcesHtml = `<div class="msg-sources" style="font-size:10px;color:var(--text-dim);margin-top:4px;">Sources: ${sources.map(s => `<code style="font-size:10px;">${esc(s)}</code>`).join(', ')}</div>`;
  }

  div.innerHTML = `
    <div class="msg-avatar ${avatarCls}">${avatar}</div>
    <div class="msg-body">
      <div class="msg-meta">
        <span>${role === 'user' ? 'You' : role === 'system' ? 'System' : 'AI Clerk'}</span>
        ${badgeHtml}
        <span>${new Date().toLocaleTimeString()}</span>
      </div>
      <div class="msg-text">${esc(text)}</div>
      ${sourcesHtml}
    </div>
  `;

  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

function appendThinking() {
  const log = document.getElementById('chat-log');
  const id = `thinking-${Date.now()}`;
  const div = document.createElement('div');
  div.id = id;
  div.className = 'chat-msg agent';
  div.innerHTML = `
    <div class="msg-avatar avatar-agent">≡ƒñû</div>
    <div class="msg-body"><div class="thinking">Sending to model and enforcing policyΓÇª</div></div>
  `;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return id;
}

function removeThinking(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function clearChat() {
  const log = document.getElementById('chat-log');
  log.innerHTML = `<div class="chat-welcome"><div class="welcome-icon">≡ƒñû</div><div class="welcome-title">AegisHarness AI Clerk</div><div class="welcome-sub">Chat cleared. Ready for next test.</div></div>`;
  document.getElementById('exec-log').innerHTML = `<div class="exec-empty">Security execution events will appear here when you send a message.</div>`;
  document.getElementById('tool-summary').classList.add('hidden');
  state.sessionId = `ui-${Date.now()}`;
  state.chatHistory = [];
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ===== SCENARIOS =====
async function loadScenarios() {
  try {
    const res = await fetch('/api/scenarios');
    const data = await res.json();
    renderScenarios(data.scenarios || []);
  } catch { /* non-critical */ }
}

function renderScenarios(scenarios) {
  const container = document.getElementById('scenarios-list');
  container.innerHTML = '';
  scenarios.forEach(s => {
    const btn = document.createElement('button');
    btn.className = `scenario-btn ${s.is_adversarial ? 'adversarial' : ''}`;
    btn.title = s.description;
    btn.innerHTML = `${s.icon} ${s.name}`;
    btn.onclick = () => {
      document.getElementById('chat-input').value = s.prompt;
      document.getElementById('chat-input').focus();
    };
    container.appendChild(btn);
  });
}

// ===== SANDBOX FILES =====
async function loadSandboxFiles() {
  try {
    const [filesRes, statusRes] = await Promise.all([
      fetch('/api/demo/files'),
      fetch('/api/demo/status'),
    ]);
    const files = await filesRes.json();
    const status = await statusRes.json();
    renderSandboxFiles(files, status);
  } catch (e) {
    document.getElementById('approved-files').textContent = 'Failed to load';
  }
}

function renderSandboxFiles(files, status) {
  const approved = document.getElementById('approved-files');
  const restricted = document.getElementById('restricted-files');
  const dbTables = document.getElementById('db-tables');

  approved.innerHTML = '';
  restricted.innerHTML = '';
  dbTables.innerHTML = '';

  // Docs
  (files.documents || []).forEach(f => {
    approved.appendChild(fileChip(f.name, 'ok', () => previewFile(`documents/${f.name}`)));
  });

  // Restricted
  (files.restricted || []).forEach(f => {
    restricted.appendChild(fileChip(f.name, 'blocked', null));
  });
  (files.structured || []).filter(f => f.name.includes('salary') || f.name.includes('payroll')).forEach(f => {
    restricted.appendChild(fileChip(f.name, 'blocked', null));
  });

  // DB tables
  (files.database_tables || []).forEach(t => {
    const cls = t.permission === 'RESTRICTED' ? 'db-blocked' : 'db-ok';
    const cb = cls === 'db-ok' ? () => previewDbTable(t.name) : null;
    dbTables.appendChild(fileChip(t.name, cls, cb));
  });
}

function fileChip(name, cls, onclick) {
  const span = document.createElement('span');
  span.className = `file-chip ${cls}`;
  span.textContent = name;
  const icon = cls === 'blocked' || cls === 'db-blocked' ? ' ≡ƒöÆ' : '';
  if (icon) span.textContent += icon;
  if (onclick) span.onclick = onclick;
  return span;
}

async function previewFile(path) {
  const preview = document.getElementById('file-preview');
  preview.innerHTML = `<div class="thinking" style="margin:24px auto;width:fit-content;">LoadingΓÇª</div>`;
  try {
    const res = await fetch(`/api/demo/file-content?path=${encodeURIComponent(path)}`);
    const data = await res.json();
    preview.innerHTML = `
      <div class="preview-header"><strong>${esc(data.filename)}</strong> ΓÇö ${esc(data.classification)} ΓÇö ${data.size_bytes} bytes</div>
      <div class="preview-content">${esc(data.content)}</div>
    `;
  } catch {
    preview.innerHTML = `<div class="preview-placeholder">Failed to load file.</div>`;
  }
}

async function previewDbTable(table) {
  const preview = document.getElementById('file-preview');
  preview.innerHTML = `<div class="preview-header"><strong>${esc(table)}</strong> ΓÇö Database Table (Permitted)</div><div class="preview-content">Use the Red Team chat to query this table via the agent.</div>`;
}

// ===== BLUE TEAM =====
async function loadLedger() {
  try {
    const res = await fetch('/api/ledger?limit=200');
    const records = await res.json();
    state.allEvents = records;
    renderEvents(records);
    updateSevBars(records);
    aggregateSocMetrics(records);

    // Also update stats
    state.stats.ledgerBlocks = records.length;
    refreshStats();
  } catch { /* non-critical */ }
}

function renderEvents(events) {
  const log = document.getElementById('event-log');
  log.innerHTML = '';

  const filter = state.eventsFilter;
  const filtered = filter === 'all' ? events : events.filter(e => e.severity === filter);

  if (!filtered.length) {
    log.innerHTML = '<div class="event-empty">No events match filter.</div>';
    return;
  }

  // Show newest first
  [...filtered].reverse().forEach(ev => {
    const row = document.createElement('div');
    const sevNum = sevToNum(ev.severity);
    row.className = `audit-event sev-${sevNum}`;
    row.title = JSON.stringify(ev.details || {}, null, 2);

    const details = ev.details || {};
    const detailStr = Object.entries(details)
      .filter(([k]) => ['prompt', 'reason', 'error', 'tool', 'attack_name', 'query', 'response_preview', 'threat_name'].includes(k))
      .map(([k, v]) => `${k}: ${String(v).slice(0, 80)}`)
      .join(' ┬╖ ');

    row.innerHTML = `
      <div class="evt-header">
        <span class="evt-type">${esc(ev.event_type)}</span>
        <span class="evt-sev sev-${sevNum}">${esc(ev.severity)}</span>
        <span class="evt-zone">[${esc(ev.source_zone)}]</span>
        <span class="evt-ts">${new Date(ev.timestamp).toLocaleTimeString()}</span>
      </div>
      <div class="evt-detail">${esc(detailStr)}</div>
      <div class="evt-session">Session: ${esc(ev.session_id)}</div>
    `;
    log.appendChild(row);
  });
}

function sevToNum(sev) {
  if (sev?.includes('1_CRITICAL')) return 1;
  if (sev?.includes('2_HIGH'))     return 2;
  if (sev?.includes('3_MEDIUM'))   return 3;
  return 4;
}

function filterEvents(filter, btn) {
  state.eventsFilter = filter;
  document.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  renderEvents(state.allEvents);
}

function setElText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function updateBar(id, count, total, label) {
  const bar = document.getElementById(`bar-${id}`);
  if (bar) bar.style.width = `${Math.min(100, Math.round((count / (total || 1)) * 100))}%`;
  const cnt = document.getElementById(`cnt-${id}`);
  if (cnt) cnt.textContent = label !== undefined ? label : count;
}

function updateSevBars(events) {
  const counts = { 1: 0, 2: 0, 3: 0, 4: 0 };
  events.forEach(e => counts[sevToNum(e.severity)]++);

  const total = events.length || 1;
  for (let i = 1; i <= 4; i++) {
    updateBar(`sev${i}`, counts[i], total, counts[i]);
  }

  // Also update SOC Defense Distribution bars
  updateBar('soc-sev4', counts[4], total, `${counts[4]} incidents`);
  updateBar('soc-sev2', counts[2], total, `${counts[2]} incidents`);
  updateBar('soc-sev1', counts[1], total, `${counts[1]} incidents`);
}

function aggregateSocMetrics(records) {
  let totalAttacks = 0;
  let successfulJailbreaks = 0;
  let modelRefusals = 0;
  let toolProposals = 0;
  let pepDenials = 0;
  let authorizedOps = 0;
  let resourceViolations = 0;
  let runtimeBlocks = 0;
  let confirmedBreaches = 0;
  let quarantineEvents = 0;
  let containments = 0;

  let catConversational = 0;
  let catJailbreaks = 0;
  let catChat = 0;
  let catMultiTurn = 0;

  records.forEach(r => {
    const d = r.details || {};
    const evType = r.event_type || '';
    const sev = r.severity || '';

    if (evType === 'ATTACK_STARTED' || evType === 'INTERACTION_LOGGED' || evType === 'SANDBOX_PROVISIONED' || d.prompt || d.user_message) {
      totalAttacks++;
    }
    if (d.pep_authorized === false || evType === 'POLICY_DENIED' || evType === 'PEP_DENIAL') {
      pepDenials++;
    }
    if (d.pep_authorized === true || evType === 'AUTHORIZED_EXECUTION' || evType === 'PEP_AUTHORIZED') {
      authorizedOps++;
    }
    if (d.refused_by_model || d.model_refused || evType === 'MODEL_REFUSAL') {
      modelRefusals++;
    }
    if (d.tool || d.tool_name || evType === 'TOOL_PROPOSAL' || evType === 'TOOL_REQUEST_EVALUATED') {
      toolProposals++;
    }
    if (sev === 'SEV-1_CRITICAL' || d.quarantined || evType === 'QUARANTINE_ACTION' || evType === 'MANUAL_QUARANTINE') {
      quarantineEvents++;
    }
    if (evType === 'CONTAINMENT_ENGAGED' || d.quarantined || evType === 'QUARANTINE_ACTION') {
      containments++;
    }
    if (sev === 'SEV-2_HIGH' || sev === 'SEV-1_CRITICAL' || d.outcome_type === 'POLICY_DENIED') {
      resourceViolations++;
      successfulJailbreaks++;
    }
    if (evType === 'RUNTIME_BLOCKED' || evType === 'EGRESS_BLOCKED' || evType === 'SYSCALL_INTERCEPT') {
      runtimeBlocks++;
    }

    const cat = (d.category || d.scenario_id || d.attack_name || '').toLowerCase();
    if (cat.includes('jailbreak') || cat.includes('tamper') || cat.includes('unauthorized') || cat.includes('resource') || cat.includes('finance')) {
      catJailbreaks++;
    } else if (cat.includes('multi') || cat.includes('turn')) {
      catMultiTurn++;
    } else if (r.source_zone === 'RED' || cat.includes('chat') || cat.includes('red')) {
      catChat++;
    } else {
      catConversational++;
    }
  });

  state.stats.total = Math.max(state.stats.total, totalAttacks);
  state.stats.blocked = Math.max(state.stats.blocked, pepDenials);
  state.stats.permitted = Math.max(state.stats.permitted, authorizedOps);
  state.stats.threats = Math.max(state.stats.threats, successfulJailbreaks);

  setElText('stat-campaigns', state.stats.campaigns || 0);
  setElText('stat-total', state.stats.total);
  setElText('stat-threats', state.stats.threats);
  setElText('stat-refusals', modelRefusals);
  setElText('stat-tool-proposals', toolProposals);
  setElText('stat-blocked', state.stats.blocked);
  setElText('stat-permitted', state.stats.permitted);
  setElText('stat-resource-violations', resourceViolations);
  setElText('stat-runtime-blocks', runtimeBlocks);
  setElText('stat-breaches', confirmedBreaches);
  setElText('stat-quarantines', quarantineEvents);
  setElText('stat-containments', containments || pepDenials);

  const catTotal = Math.max(1, catConversational + catJailbreaks + catChat + catMultiTurn);
  updateBar('cat-conv', catConversational, catTotal, `${catConversational} attacks`);
  updateBar('cat-jailbreak', catJailbreaks, catTotal, `${catJailbreaks} attacks`);
  updateBar('cat-chat', catChat, catTotal, `${catChat} attacks`);
  updateBar('cat-multiturn', catMultiTurn, catTotal, `${catMultiTurn} attacks`);
}

async function verifyChain() {
  const card = document.getElementById('chain-card');
  const statusEl = document.getElementById('chain-status');
  const detailEl = document.getElementById('chain-detail');

  statusEl.textContent = 'VerifyingΓÇª';
  card.className = 'chain-card';

  try {
    const res = await fetch('/api/ledger/verify');
    const data = await res.json();

    document.getElementById('chain-blocks').textContent = data.block_count;
    document.getElementById('chain-tip').textContent = data.tip_hash ? data.tip_hash.slice(0, 12) + 'ΓÇª' : 'N/A';

    if (data.is_valid) {
      card.className = 'chain-card valid';
      document.getElementById('chain-icon').textContent = 'Γ£à';
      statusEl.textContent = 'Chain Integrity Verified';
      detailEl.textContent = data.message;
      state.stats.integrity = true;
    } else {
      card.className = 'chain-card invalid';
      document.getElementById('chain-icon').textContent = 'Γ¢ö';
      statusEl.textContent = 'Chain COMPROMISED';
      detailEl.textContent = data.message;
      state.stats.integrity = false;
    }
    refreshStats();
  } catch (e) {
    statusEl.textContent = 'Verification failed';
    detailEl.textContent = e.message;
  }
}

async function triggerManualQuarantine() {
  const sessInput = document.getElementById('quarantine-session');
  const sessionId = sessInput.value.trim();
  if (!sessionId) return alert('Enter a session ID to quarantine.');

  try {
    const res = await fetch('/api/quarantine', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: sessionId, reason: 'Manual operator kill switch from dashboard' }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Quarantine failed: ${data.detail}`);
      return;
    }
    showQuarantineBanner(`Manually quarantined session ${data.session_id} in ${data.latency_ms?.toFixed(1) || 0}ms`);
    sessInput.value = '';
    setTimeout(loadLedger, 500);
  } catch (e) {
    alert(`Error: ${e.message}`);
  }
}

// ===== QUARANTINE BANNER =====
function showQuarantineBanner(reason) {
  const banner = document.getElementById('quarantine-banner');
  if (banner) {
    document.getElementById('quarantine-reason').textContent = ` ΓÇö ${reason}`;
    banner.classList.remove('hidden');
  }
  updateSandboxStateChips('QUARANTINED');
}

function dismissQuarantine() {
  const banner = document.getElementById('quarantine-banner');
  if (banner) banner.classList.add('hidden');
  if (!state.isQuarantined) {
    updateSandboxStateChips('ACTIVE');
  }
}

function lockChatForQuarantine(latencyMs, reason) {
  state.isQuarantined = true;
  const input = document.getElementById('chat-input');
  const btn = document.getElementById('send-btn');
  if (input) {
    input.disabled = true;
    input.placeholder = '≡ƒöÆ Workload quarantined. Chat session locked. Click "+ New Sandbox" to continue.';
  }
  if (btn) {
    btn.disabled = true;
    btn.textContent = 'Locked ≡ƒöÆ';
  }

  const newBtn = document.getElementById('btn-new-sandbox');
  if (newBtn) {
    newBtn.classList.add('pulse-highlight');
  }

  showQuarantineBanner(`Workload slaughtered in ${latencyMs ? latencyMs.toFixed(1) : '1.5'}ms (${reason || 'Security policy violation'})`);
  updateSandboxStateChips('QUARANTINED');

  appendChatMsg('system', `Workload slaughtered in ${latencyMs ? latencyMs.toFixed(1) : '1.5'}ms. Zero-trust isolation policy has permanently locked this session to prevent further exploitation. Click "+ New Sandbox" above to launch a clean environment.`, 'denied');
}

function createNewSandbox() {
  state.sessionId = `ui-${Date.now()}`;
  state.chatHistory = [];
  state.isQuarantined = false;

  const input = document.getElementById('chat-input');
  const btn = document.getElementById('send-btn');
  if (input) {
    input.disabled = false;
    input.placeholder = 'Type a message or select a scenario aboveΓÇª';
  }
  if (btn) {
    btn.disabled = false;
    btn.textContent = 'Send Γû╢';
  }

  const newBtn = document.getElementById('btn-new-sandbox');
  if (newBtn) {
    newBtn.classList.remove('pulse-highlight');
  }

  const log = document.getElementById('chat-log');
  if (log) {
    log.innerHTML = `<div class="chat-welcome"><div class="welcome-icon">≡ƒ¢í∩╕Å</div><div class="welcome-title">New Disposable Sandbox Provisioned</div><div class="welcome-sub">Workload is active and monitored. Ready for testing.</div></div>`;
  }
  const execLog = document.getElementById('exec-log');
  if (execLog) {
    execLog.innerHTML = `<div class="exec-empty">Security execution events will appear here when you send a message.</div>`;
  }
  const toolSum = document.getElementById('tool-summary');
  if (toolSum) toolSum.classList.add('hidden');

  dismissQuarantine();
  updateSandboxStateChips('ACTIVE');

  // Pre-fill Blue Team manual quarantine session
  const qInput = document.getElementById('quarantine-session');
  if (qInput) qInput.value = state.sessionId;

  // Proactively provision sandbox on backend
  fetch('/api/sandbox/provision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: state.sessionId }),
  }).catch(() => {});

  if (input) input.focus();
}

// ===== STATE CHIPS =====
function updateSandboxStateChips(state) {
  const cls = {
    'IDLE': 'state-idle',
    'ACTIVE': 'state-ready',
    'EXECUTING': 'state-executing',
    'THREAT_DETECTED': 'state-threat',
    'QUARANTINED': 'state-quarantined',
  }[state] || 'state-idle';

  ['sandbox-state-chip', 'sandbox-state-detail', 'stat-sandbox-state'].forEach(id => {
    const el = document.getElementById(id);
    if (!el) return;
    el.className = el.className.replace(/state-\w+/g, '');
    if (id.startsWith('stat')) {
      el.textContent = state;
    } else {
      el.className += ` state-chip ${cls}`;
      el.textContent = state;
    }
  });
}

// ===== STATS BAR =====
async function refreshStats() {
  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    state.stats.ledgerBlocks = data.total_ledger_records;
    state.stats.integrity = data.ledger_integrity_valid;

    setElText('stat-ledger', data.total_ledger_records);
    const elIntegrity = document.getElementById('stat-integrity');
    if (elIntegrity) {
      elIntegrity.textContent = data.ledger_integrity_valid ? 'Γ£ô Valid' : 'Γ£ù Broken';
      elIntegrity.style.color = data.ledger_integrity_valid ? 'var(--green)' : 'var(--red)';
    }
  } catch { /* non-critical */ }

  setElText('stat-total', state.stats.total);
  setElText('stat-threats', state.stats.threats);
  setElText('stat-blocked', state.stats.blocked);
  setElText('stat-permitted', state.stats.permitted);

  if (state.allEvents && state.allEvents.length) {
    aggregateSocMetrics(state.allEvents);
  }
}

// ===== MODEL STATUS =====
async function updateModelChip() {
  const chip = document.getElementById('model-status-chip');
  if (!chip) return;
  const label = document.getElementById('model-chip-label');
  const dot = chip.querySelector('.dot');

  try {
    const res = await fetch('/api/agent/status');
    const data = await res.json();
    if (data.online) {
      if (dot) dot.className = 'dot dot-green';
      if (label) label.textContent = `${data.model} — Online`;
    } else {
      if (dot) dot.className = 'dot dot-yellow';
      if (label) label.textContent = `${data.model} — Start Ollama`;
    }
  } catch {
    if (dot) dot.className = 'dot dot-red';
    if (label) label.textContent = 'API Unreachable';
  }
}

// ===== DEMO RESET =====
async function resetDemo() {
  if (!confirm('Reset the demo environment? This clears sandbox files and resets the demo database.')) return;
  try {
    const res = await fetch('/api/demo/reset', { method: 'POST' });
    const data = await res.json();
    clearChat();
    loadSandboxFiles();
    alert(`Demo environment reset. ${data.message || ''}`);
  } catch (e) {
    alert(`Reset failed: ${e.message}`);
  }
}

// ===== INIT =====
async function init() {
  connectWS();
  loadScenarios();
  refreshStats();
  loadLedger();
  loadSandboxFiles();
  updateModelChip();

  // Sync model select to label
  const activeLabel = document.getElementById('active-model-label');
  if (activeLabel) activeLabel.textContent = state.activeModel;

  // Pre-fill Blue Team operator kill switch with active session ID
  const qInput = document.getElementById('quarantine-session');
  if (qInput) qInput.value = state.sessionId;

  // Initialize active disposable sandbox for initial session
  fetch('/api/sandbox/provision', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ session_id: state.sessionId }),
  }).then(() => {
    updateSandboxStateChips('ACTIVE');
  }).catch(() => {});

  // Poll for stats every 10s
  setInterval(refreshStats, 10000);
  setInterval(updateModelChip, 30000);
}

document.addEventListener('DOMContentLoaded', init);
