/**
 * Vault Controller - AESX Cryptographic Database Vault Explorer
 * Demonstrates Field-Level Encryption and AES-GCM Tamper Resistance
 */

const Vault = {
  profiles: [],

  init() {
    this.fetchVault();
    this.setupTamperTest();
    this.setupRefresh();
  },

  async fetchVault() {
    const container = document.getElementById('vault-profiles-container');
    if (!container) return;

    try {
      const res = await fetch('/api/dlp/vault');
      const data = await res.json();
      if (data.success) {
        this.profiles = data.vaultProfiles;
        this.renderVault(data);
      }
    } catch (err) {
      container.innerHTML = `<div style="color: var(--rose-danger); padding: 2rem;">Error loading vault: ${err.message}</div>`;
    }
  },

  renderVault(data) {
    const container = document.getElementById('vault-profiles-container');
    if (!container) return;

    const { keyFingerprint, algorithm, vaultProfiles } = data;

    let html = `
      <div class="glass-card" style="margin-bottom: 1.5rem; background: rgba(13, 20, 36, 0.85); border-left: 4px solid var(--purple-accent);">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
          <div>
            <strong style="color: var(--purple-accent); font-size: 1rem;">Active Cryptographic Engine:</strong>
            <span style="color: #ffffff; font-family: var(--font-mono); margin-left: 0.5rem;">${algorithm}</span>
          </div>
          <div>
            <span style="color: var(--text-muted); font-size: 0.8rem;">Key Fingerprint:</span>
            <code style="color: var(--cyan-primary); background: #070c17; padding: 0.2rem 0.5rem; border-radius: 4px; margin-left: 0.4rem;">
              ${keyFingerprint}
            </code>
          </div>
        </div>
      </div>
    `;

    if (!vaultProfiles || vaultProfiles.length === 0) {
      html += '<p style="color: var(--text-dim); text-align: center; padding: 2rem;">No vault profiles found.</p>';
      container.innerHTML = html;
      return;
    }

    html += vaultProfiles.map(p => `
      <div class="vault-record-card">
        <div style="display: flex; justify-content: space-between; align-items: center; padding-bottom: 0.6rem; border-bottom: 1px solid var(--border-subtle);">
          <div>
            <span style="font-weight: 700; font-size: 1.05rem; color: #ffffff;">${p.fullName || p.username}</span>
            <span style="font-size: 0.8rem; color: var(--text-muted); margin-left: 0.5rem;">(@${p.username})</span>
          </div>
          <div style="display: flex; gap: 0.5rem; align-items: center;">
            <span class="badge badge-${p.category?.toLowerCase() || 'benign'}">${p.category}</span>
            <span class="badge" style="background: rgba(255,255,255,0.06);">${p.status}</span>
          </div>
        </div>

        <div class="vault-columns">
          <!-- Raw SQLite Encrypted Storage -->
          <div class="vault-col-box">
            <div style="font-weight: 700; color: #38bdf8; margin-bottom: 0.6rem; display: flex; align-items: center; justify-content: space-between;">
              <span>🗄️ Raw SQLite Storage (Field-Level Encrypted)</span>
              <span style="font-size: 0.7rem; color: var(--text-dim);">AESX Ciphertext</span>
            </div>

            <div style="margin-bottom: 0.6rem;">
              <div class="vault-field-label">Credit Card Ciphertext:</div>
              <div class="vault-cipher-val">${p.encrypted.creditCard}</div>
            </div>

            <div style="margin-bottom: 0.6rem;">
              <div class="vault-field-label">Shipping Address Ciphertext:</div>
              <div class="vault-cipher-val">${p.encrypted.address}</div>
            </div>

            <div>
              <div class="vault-field-label">Phone Ciphertext:</div>
              <div class="vault-cipher-val">${p.encrypted.phone}</div>
            </div>
          </div>

          <!-- Authorized Decrypted View -->
          <div class="vault-col-box">
            <div style="font-weight: 700; color: var(--emerald-success); margin-bottom: 0.6rem; display: flex; align-items: center; justify-content: space-between;">
              <span>🔓 Authorized Cloud Decrypted View</span>
              <span style="font-size: 0.7rem; color: var(--emerald-success);">Auth Verified</span>
            </div>

            <div style="margin-bottom: 0.6rem;">
              <div class="vault-field-label">Credit Card (Decrypted &amp; Masked):</div>
              <div class="vault-decrypted-val">${p.decrypted.creditCard}</div>
            </div>

            <div style="margin-bottom: 0.6rem;">
              <div class="vault-field-label">Shipping Address:</div>
              <div class="vault-decrypted-val">${p.decrypted.address}</div>
            </div>

            <div>
              <div class="vault-field-label">Phone:</div>
              <div class="vault-decrypted-val">${p.decrypted.phone}</div>
            </div>
          </div>
        </div>
      </div>
    `).join('');

    container.innerHTML = html;
  },

  // Setup Tamper Test Button
  setupTamperTest() {
    const btn = document.getElementById('btn-test-tamper');
    const resultBox = document.getElementById('vault-tamper-result');

    if (btn && resultBox) {
      btn.addEventListener('click', async () => {
        btn.disabled = true;
        btn.textContent = 'Simulating Bit Tamper...';

        try {
          const res = await fetch('/api/dlp/vault/tamper-test', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
          });

          const data = await res.json();
          btn.disabled = false;
          btn.textContent = '🧪 Simulate Cipher Tampering';

          if (data.success) {
            const { result } = data;
            resultBox.style.display = 'block';
            resultBox.innerHTML = `
              <div class="glass-card" style="border-left: 4px solid var(--rose-danger); background: rgba(244, 63, 94, 0.08);">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
                  <strong style="color: var(--rose-danger); font-size: 1.05rem;">
                    🛡️ Cryptographic Tamper Test: PASSED (Alteration Rejected)
                  </strong>
                  <span class="badge badge-critical">INTEGRITY VERIFIED</span>
                </div>
                <p style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 0.6rem;">
                  ${result.explanation}
                </p>
                <div style="font-size: 0.78rem; font-family: var(--font-mono); margin-bottom: 0.4rem;">
                  <strong>Original Valid Token:</strong><br>
                  <span style="color: var(--emerald-success); word-break: break-all;">${result.originalToken}</span>
                </div>
                <div style="font-size: 0.78rem; font-family: var(--font-mono); margin-bottom: 0.6rem;">
                  <strong>Corrupted (Flipped Bit) Token:</strong><br>
                  <span style="color: #f87171; word-break: break-all;">${result.corruptedToken}</span>
                </div>
                <div class="code-block" style="font-size: 0.75rem; color: #fca5a5;">
                  Resulting Decryption Failure: ${result.errorDetected}
                </div>
              </div>
            `;
            App.showToast('Tamper Caught!', 'success', 'AES-GCM AuthTag caught the bit alteration immediately.');
          }
        } catch (err) {
          btn.disabled = false;
          btn.textContent = '🧪 Simulate Cipher Tampering';
          App.showToast('Tamper Test Error', 'danger', err.message);
        }
      });
    }
  },

  setupRefresh() {
    document.getElementById('btn-refresh-vault')?.addEventListener('click', () => {
      this.fetchVault();
      App.showToast('Vault Synchronized', 'info', 'Database vault records updated.');
    });
  }
};

window.addEventListener('DOMContentLoaded', () => {
  window.Vault = Vault;
  Vault.init();
});
