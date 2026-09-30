/**
 * App Core - State, Navigation, SSE Telemetry, and Notifications
 */

const App = {
  state: {
    currentView: 'storefront',
    currentSocTab: 'soc-overview',
    currentUser: {
      username: 'Alice (Demo Customer)',
      role: 'customer',
      category: 'Benign',
      riskScore: 0,
      token: null
    },
    cart: [],
    sseConnected: false
  },

  init() {
    this.setupViewNavigation();
    this.setupSSE();
    this.setupQuickAttackModal();
  },

  // View Navigation (Storefront vs SOC)
  setupViewNavigation() {
    const btnStore = document.getElementById('btn-view-store');
    const btnSoc = document.getElementById('btn-view-soc');
    const viewStore = document.getElementById('view-storefront');
    const viewSoc = document.getElementById('view-soc');

    btnStore.addEventListener('click', () => {
      this.state.currentView = 'storefront';
      btnStore.classList.add('active');
      btnSoc.classList.remove('active');
      viewStore.classList.add('active');
      viewSoc.classList.remove('active');
    });

    btnSoc.addEventListener('click', () => {
      this.state.currentView = 'soc';
      btnSoc.classList.add('active');
      btnStore.classList.remove('active');
      viewSoc.classList.add('active');
      viewStore.classList.remove('active');

      // Refresh SOC metrics & incidents on entry
      if (window.SOC) {
        window.SOC.fetchStats();
        window.SOC.fetchIncidents();
        window.SOC.fetchUsers();
      }
    });

    // SOC Subnavigation tabs
    document.querySelectorAll('.soc-tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        document.querySelectorAll('.soc-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.soc-tab-content').forEach(c => c.style.display = 'none');

        btn.classList.add('active');
        const targetId = `tab-${btn.dataset.soctab}`;
        const targetEl = document.getElementById(targetId);
        if (targetEl) targetEl.style.display = 'block';

        if (btn.dataset.soctab === 'soc-vault' && window.Vault) {
          window.Vault.fetchVault();
        } else if (btn.dataset.soctab === 'soc-users' && window.SOC) {
          window.SOC.fetchUsers();
        }
      });
    });
  },

  // Server-Sent Events (SSE) for Real-Time Threat Broadcasting
  setupSSE() {
    const streamStatusEl = document.getElementById('stream-status');

    try {
      const evtSource = new EventSource('/api/dlp/stream');

      evtSource.onopen = () => {
        this.state.sseConnected = true;
        if (streamStatusEl) streamStatusEl.textContent = 'LIVE STREAM';
      };

      evtSource.addEventListener('incident', (event) => {
        const incident = JSON.parse(event.data);
        this.handleIncomingIncident(incident);
      });

      evtSource.onerror = () => {
        this.state.sseConnected = false;
        if (streamStatusEl) streamStatusEl.textContent = 'RECONNECTING';
      };
    } catch (err) {
      console.warn('SSE connection error:', err);
    }
  },

  // Process live security incident from stream
  handleIncomingIncident(incident) {
    // Show toast alert
    const isCritical = incident.threatLevel === 'CRITICAL';
    this.showToast(
      `${incident.threatLevel} Alert: ${incident.ruleMatched}`,
      isCritical ? 'danger' : 'warning',
      `User ${incident.userIdentifier} triggered action: ${incident.actionTaken}`
    );

    // If SOC view active or background update
    if (window.SOC) {
      window.SOC.addIncidentToFeed(incident);
      window.SOC.fetchStats();
    }

    // If user's own status changed, update header pill
    if (incident.userCategory) {
      this.updateUserCategoryPill(incident.userCategory, incident.riskScore);
    }
  },

  // Update user category badge in nav
  updateUserCategoryPill(category, riskScore) {
    const pill = document.getElementById('nav-user-category');
    if (!pill) return;
    pill.textContent = `${category} (${riskScore})`;
    pill.className = `badge badge-${category.toLowerCase()}`;
  },

  // Toast Notification System
  showToast(title, type = 'info', message = '') {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    let icon = 'ℹ️';
    if (type === 'danger') icon = '🚨';
    if (type === 'warning') icon = '⚠️';
    if (type === 'success') icon = '✅';

    toast.innerHTML = `
      <div style="font-size: 1.3rem;">${icon}</div>
      <div style="flex: 1;">
        <div style="font-weight: 700; font-size: 0.9rem; margin-bottom: 0.2rem;">${title}</div>
        ${message ? `<div style="font-size: 0.8rem; color: var(--text-muted);">${message}</div>` : ''}
      </div>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(40px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  },

  // Quick Attack Trigger Modal
  setupQuickAttackModal() {
    const btnQuick = document.getElementById('btn-quick-attack');
    if (btnQuick) {
      btnQuick.addEventListener('click', () => {
        // Switch directly to SOC Attack Lab tab
        const btnSoc = document.getElementById('btn-view-soc');
        btnSoc.click();
        const tabAttackBtn = document.querySelector('[data-soctab="soc-attack-lab"]');
        if (tabAttackBtn) tabAttackBtn.click();
      });
    }
  }
};

window.addEventListener('DOMContentLoaded', () => {
  App.init();
});
