/**
 * SOC Controller - Security Operations Center Dashboard,
 * Real-Time Incident Stream, User Risk Matrix, and Attack Simulator
 */

const SOC = {
  incidents: [],
  users: [],

  init() {
    this.fetchStats();
    this.fetchIncidents();
    this.setupAttackSimulator();
    this.setupIncidentModal();
    this.setupRefreshButtons();
  },

  // Fetch KPI Stats
  async fetchStats() {
    try {
      const res = await fetch('/api/dlp/stats');
      const data = await res.json();
      if (data.success) {
        const { stats } = data;
        const totalEl = document.getElementById('kpi-total-incidents');
        const critEl = document.getElementById('kpi-critical-incidents');
        const blockedEl = document.getElementById('kpi-blocked-actions');
        const keyEl = document.getElementById('kpi-key-fingerprint');

        if (totalEl) totalEl.textContent = stats.totalIncidents;
        if (critEl) critEl.textContent = stats.criticalIncidents;
        if (blockedEl) blockedEl.textContent = stats.blockedActions;
        if (keyEl) keyEl.textContent = `Vault: ${stats.aesxKeyFingerprint}`;
      }
    } catch (err) {
      console.warn('Error fetching stats:', err);
    }
  },

  // Fetch Incidents Audit Log
  async fetchIncidents() {
    try {
      const res = await fetch('/api/dlp/incidents');
      const data = await res.json();
      if (data.success) {
        this.incidents = data.incidents;
        this.renderIncidents(this.incidents);
      }
    } catch (err) {
      console.warn('Error fetching incidents:', err);
    }
  },

  // Render Incidents Table
  renderIncidents(incidents) {
    const tbody = document.getElementById('incidents-table-body');
    if (!tbody) return;

    if (!incidents || incidents.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">
            No security incidents recorded. System running clean.
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = incidents.map(inc => {
      const threatClass = `badge-${inc.threat_level?.toLowerCase() || 'low'}`;
      const timeStr = new Date(inc.timestamp).toLocaleTimeString();
      const payloadShort = (inc.request_payload || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const payloadDisplay = payloadShort.length > 55 ? payloadShort.substring(0, 52) + '...' : payloadShort;

      return `
        <tr style="cursor: pointer;" data-id="${inc.id}">
          <td style="color: var(--text-dim);">${timeStr}</td>
          <td style="font-weight: 600; color: var(--cyan-primary);">${inc.user_identifier}</td>
          <td>
            <span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">
              ${inc.detection_layer}
            </span>
          </td>
          <td style="max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
            ${inc.rule_matched}
          </td>
          <td><span class="badge ${threatClass}">${inc.threat_level}</span></td>
          <td>
            <span class="badge" style="background: rgba(244,63,94,0.15); color: #fda4af;">
              ${inc.action_taken}
            </span>
          </td>
          <td style="color: #94a3b8; font-family: var(--font-mono); font-size: 0.78rem;">
            <code>${payloadDisplay || '[Empty]'}</code>
          </td>
        </tr>
      `;
    }).join('');

    // Attach row click to open detail modal
    tbody.querySelectorAll('tr[data-id]').forEach(row => {
      row.addEventListener('click', () => {
        const id = parseInt(row.dataset.id, 10);
        this.openIncidentModal(id);
      });
    });
  },

  // Real-time incident prepended to feed via SSE
  addIncidentToFeed(incident) {
    const tbody = document.getElementById('incidents-table-body');
    if (!tbody) return;

    // Check if placeholder row exists
    if (tbody.children.length === 1 && tbody.children[0].innerText.includes('No security incidents')) {
      tbody.innerHTML = '';
    }

    const threatClass = `badge-${incident.threatLevel?.toLowerCase() || 'high'}`;
    const timeStr = new Date(incident.timestamp).toLocaleTimeString();
    const payloadShort = (incident.payloadSnippet || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');

    const tr = document.createElement('tr');
    tr.className = 'incident-row-new';
    tr.style.cursor = 'pointer';
    tr.dataset.id = incident.id;
    tr.innerHTML = `
      <td style="color: var(--cyan-primary); font-weight: 700;">${timeStr} ⚡</td>
      <td style="font-weight: 600; color: var(--cyan-primary);">${incident.userIdentifier}</td>
      <td>
        <span class="badge" style="background: rgba(255,255,255,0.06); color: var(--text-muted);">
          ${incident.detectionLayer}
        </span>
      </td>
      <td style="max-width: 220px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
        ${incident.ruleMatched}
      </td>
      <td><span class="badge ${threatClass}">${incident.threatLevel}</span></td>
      <td>
        <span class="badge" style="background: rgba(244,63,94,0.15); color: #fda4af;">
          ${incident.actionTaken}
        </span>
      </td>
      <td style="color: #94a3b8; font-family: var(--font-mono); font-size: 0.78rem;">
        <code>${payloadShort}</code>
      </td>
    `;

    tr.addEventListener('click', () => {
      this.openIncidentModal(incident.id);
    });

    tbody.insertBefore(tr, tbody.firstChild);
  },

  // Incident Detail Modal
  setupIncidentModal() {
    const modal = document.getElementById('incident-modal');
    const closeBtn = document.getElementById('btn-close-incident-modal');
    if (closeBtn && modal) {
      closeBtn.addEventListener('click', () => modal.classList.remove('active'));
    }
  },

  async openIncidentModal(incidentId) {
    const modal = document.getElementById('incident-modal');
    const body = document.getElementById('incident-modal-body');
    if (!modal || !body) return;

    // Find incident from memory or API
    let inc = this.incidents.find(i => i.id === incidentId);
    if (!inc) {
      const res = await fetch('/api/dlp/incidents');
      const data = await res.json();
      if (data.success) {
        this.incidents = data.incidents;
        inc = this.incidents.find(i => i.id === incidentId);
      }
    }

    if (!inc) return;

    let parsedDetails = {};
    try {
      parsedDetails = typeof inc.details === 'string' ? JSON.parse(inc.details) : inc.details;
    } catch (e) {
      parsedDetails = { raw: inc.details };
    }

    body.innerHTML = `
      <div style="display: flex; gap: 0.8rem; margin-bottom: 1.2rem;">
        <span class="badge badge-${inc.threat_level?.toLowerCase() || 'high'}">${inc.threat_level} THREAT</span>
        <span class="badge badge-assaulter">${inc.action_taken}</span>
        <span class="badge" style="background: rgba(255,255,255,0.08);">${inc.detection_layer}</span>
      </div>

      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1.2rem; font-size: 0.85rem;">
        <div><strong>User Identifier:</strong> ${inc.user_identifier}</div>
        <div><strong>Origin IP:</strong> ${inc.ip_address}</div>
        <div><strong>Endpoint:</strong> <code>${inc.endpoint}</code></div>
        <div><strong>Timestamp:</strong> ${new Date(inc.timestamp).toLocaleString()}</div>
      </div>

      <div style="margin-bottom: 1.2rem;">
        <label style="display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.3rem;">Triggered Rules:</label>
        <div style="font-weight: 600; color: #f87171;">${inc.rule_matched}</div>
      </div>

      <div style="margin-bottom: 1.2rem;">
        <label style="display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.3rem;">Raw Payload Caught:</label>
        <div class="code-block" style="color: #f87171;">${(inc.request_payload || '').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
      </div>

      <div>
        <label style="display: block; font-size: 0.8rem; color: var(--text-muted); margin-bottom: 0.3rem;">Detailed Telemetry Diagnostics:</label>
        <pre class="code-block" style="font-size: 0.75rem; color: #38bdf8;">${JSON.stringify(parsedDetails, null, 2)}</pre>
      </div>
    `;

    modal.classList.add('active');
  },

  // User Threat Categorization View
  async fetchUsers() {
    try {
      const res = await fetch('/api/dlp/users');
      const data = await res.json();
      if (data.success) {
        this.users = data.users;
        this.renderUserMatrix(this.users);
      }
    } catch (err) {
      console.warn('Error fetching users:', err);
    }
  },

  renderUserMatrix(users) {
    const benignList = document.getElementById('users-benign-list');
    const suspiciousList = document.getElementById('users-suspicious-list');
    const assaultersList = document.getElementById('users-assaulters-list');

    const benignCount = document.getElementById('count-benign-users');
    const suspiciousCount = document.getElementById('count-suspicious-users');
    const assaultersCount = document.getElementById('count-assaulters');

    const benign = users.filter(u => u.category === 'Benign');
    const suspicious = users.filter(u => u.category === 'Suspicious');
    const assaulters = users.filter(u => u.category === 'Assaulter');

    if (benignCount) benignCount.textContent = benign.length;
    if (suspiciousCount) suspiciousCount.textContent = suspicious.length;
    if (assaultersCount) assaultersCount.textContent = assaulters.length;

    const renderCard = (u, color) => `
      <div class="user-item-card">
        <div class="user-item-top">
          <span class="user-item-name">${u.username}</span>
          <span class="badge" style="background: rgba(255,255,255,0.06); font-size: 0.7rem;">${u.role}</span>
        </div>
        <div style="font-size: 0.78rem; color: var(--text-muted);">${u.email}</div>
        <div class="risk-meter">
          <div class="risk-bar" style="width: ${Math.max(5, u.risk_score)}%; background: ${color};"></div>
        </div>
        <div style="display: flex; justify-content: space-between; align-items: center; font-size: 0.75rem;">
          <span style="color: ${color}; font-weight: 700;">Risk Score: ${u.risk_score}/100</span>
          <span style="color: var(--text-dim); text-transform: uppercase;">${u.status}</span>
        </div>
        <div style="display: flex; gap: 0.4rem; margin-top: 0.8rem;">
          ${u.category !== 'Assaulter' ? `
            <button class="btn btn-danger btn-user-action" data-id="${u.id}" data-action="RESTRICT" style="padding: 0.25rem 0.55rem; font-size: 0.72rem; flex: 1;">
              Quarantine
            </button>
          ` : ''}
          <button class="btn btn-secondary btn-user-action" data-id="${u.id}" data-action="RESET" style="padding: 0.25rem 0.55rem; font-size: 0.72rem; flex: 1;">
            Reset Risk
          </button>
        </div>
      </div>
    `;

    if (benignList) {
      benignList.innerHTML = benign.length > 0 ? benign.map(u => renderCard(u, 'var(--emerald-success)')).join('') : '<p style="color: var(--text-dim); padding: 1rem;">No benign users</p>';
    }
    if (suspiciousList) {
      suspiciousList.innerHTML = suspicious.length > 0 ? suspicious.map(u => renderCard(u, 'var(--amber-warning)')).join('') : '<p style="color: var(--text-dim); padding: 1rem;">No suspicious users</p>';
    }
    if (assaultersList) {
      assaultersList.innerHTML = assaulters.length > 0 ? assaulters.map(u => renderCard(u, 'var(--rose-danger)')).join('') : '<p style="color: var(--text-dim); padding: 1rem;">No quarantined assaulters</p>';
    }

    // Attach admin actions
    document.querySelectorAll('.btn-user-action').forEach(btn => {
      btn.addEventListener('click', async () => {
        const userId = btn.dataset.id;
        const action = btn.dataset.action;
        await this.handleUserAction(userId, action);
      });
    });
  },

  async handleUserAction(userId, action) {
    try {
      const res = await fetch(`/api/dlp/users/${userId}/action`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action })
      });
      const data = await res.json();
      if (data.success) {
        App.showToast('Action Executed', 'success', data.message);
        this.fetchUsers();
        this.fetchStats();
      }
    } catch (err) {
      App.showToast('Action Failed', 'danger', err.message);
    }
  },

  // Setup Attack Simulator
  setupAttackSimulator() {
    const feedbackBox = document.getElementById('sim-attack-feedback');

    document.querySelectorAll('.btn-sim-attack').forEach(btn => {
      btn.addEventListener('click', async () => {
        const attackType = btn.dataset.attack;
        btn.disabled = true;
        btn.textContent = 'Simulating Attack...';

        try {
          const res = await fetch('/api/dlp/simulate-attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ attackType })
          });

          const data = await res.json();
          btn.disabled = false;
          btn.textContent = 'Launch Attack Again';

          if (data.success && feedbackBox) {
            const { attackResult } = data;
            feedbackBox.style.display = 'block';
            feedbackBox.innerHTML = `
              <div class="glass-card" style="border-left: 4px solid var(--rose-danger); background: rgba(244, 63, 94, 0.08);">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.6rem;">
                  <strong style="color: var(--rose-danger); font-size: 1.15rem;">
                    🎯 ${attackResult.name} Neutralized!
                  </strong>
                  <span class="badge badge-critical">DLP ACTION: ${attackResult.inspection?.finalAction}</span>
                </div>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.6rem;">
                  <strong>Vector:</strong> ${attackResult.vector}
                </p>
                <div class="code-block" style="font-size: 0.8rem; color: #f87171; margin-bottom: 0.8rem;">
                  Payload Tested: ${attackResult.payload}
                </div>
                <div style="font-size: 0.82rem; color: var(--text-main);">
                  ✓ Rule Triggered: <strong>${attackResult.inspection?.contentReport?.matches?.map(m => m.ruleName).join(', ') || 'Contextual Anomaly'}</strong><br>
                  ✓ User Categorized As: <strong style="color: var(--rose-danger);">${attackResult.inspection?.contextualReport?.newCategory}</strong> (Score: ${attackResult.inspection?.contextualReport?.currentRiskScore})<br>
                  ✓ Enforcement: <strong>${attackResult.inspection?.finalAction}</strong> (Honeypot Active: ${attackResult.inspection?.serveHoneytoken ? 'YES' : 'NO'})
                </div>
              </div>
            `;

            App.showToast('Attack Intercepted!', 'danger', `${attackResult.name} was caught and quarantined.`);
            this.fetchStats();
            this.fetchIncidents();
            this.fetchUsers();
          }
        } catch (err) {
          btn.disabled = false;
          btn.textContent = 'Launch Attack';
          App.showToast('Simulation Error', 'danger', err.message);
        }
      });
    });
  },

  // Setup refresh buttons
  setupRefreshButtons() {
    document.getElementById('btn-refresh-incidents')?.addEventListener('click', () => {
      this.fetchIncidents();
      this.fetchStats();
      App.showToast('Incidents Updated', 'info', 'Feed synchronized with database audit log.');
    });

    document.getElementById('btn-clear-feed-ui')?.addEventListener('click', () => {
      const tbody = document.getElementById('incidents-table-body');
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-dim); padding: 2rem;">Feed cleared from view. New incidents will stream here.</td></tr>';
      }
    });

    document.getElementById('btn-refresh-users')?.addEventListener('click', () => {
      this.fetchUsers();
      App.showToast('Users Synchronized', 'info', 'User risk directory refreshed.');
    });
  }
};

window.addEventListener('DOMContentLoaded', () => {
  window.SOC = SOC;
  SOC.init();
});
