/**
 * SQLite Database Engine for Detecting Data Leaks Project
 * Leverages Node's native DatabaseSync with AESX field-level encryption for PII.
 */

const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const aesx = require('../crypto/aesx');
const { products, demoUsers, honeytokens } = require('./seedData');

const DB_PATH = path.join(__dirname, '../../data_leaks.db');
const db = new DatabaseSync(DB_PATH);

function initDatabase() {
  // 1. Users Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'customer',
      status TEXT DEFAULT 'active',
      risk_score INTEGER DEFAULT 0,
      category TEXT DEFAULT 'Benign',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 2. Customer Profiles (Field-Level Encrypted using AESX)
  db.exec(`
    CREATE TABLE IF NOT EXISTS customer_profiles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      full_name TEXT NOT NULL,
      phone_encrypted TEXT NOT NULL,
      address_encrypted TEXT NOT NULL,
      credit_card_encrypted TEXT NOT NULL,
      credit_card_last4 TEXT NOT NULL,
      balance REAL DEFAULT 0.00,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);

  // 3. Products Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      price REAL NOT NULL,
      stock INTEGER NOT NULL,
      rating REAL DEFAULT 4.5,
      description TEXT,
      image_url TEXT
    )
  `);

  // 4. Orders Table
  db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      customer_name TEXT,
      total_amount REAL NOT NULL,
      items_json TEXT NOT NULL,
      shipping_encrypted TEXT,
      payment_status TEXT DEFAULT 'CONFIRMED',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // 5. User Messages / Chat Inquiries
  db.exec(`
    CREATE TABLE IF NOT EXISTS user_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      message_text TEXT NOT NULL,
      inspection_status TEXT DEFAULT 'CLEAN',
      threat_level TEXT DEFAULT 'CLEAN',
      leak_indicators TEXT,
      action_taken TEXT DEFAULT 'ALLOWED',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 6. Security Incidents / DLP Audit Log
  db.exec(`
    CREATE TABLE IF NOT EXISTS security_incidents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      user_identifier TEXT,
      ip_address TEXT,
      endpoint TEXT,
      request_payload TEXT,
      detection_layer TEXT,
      rule_matched TEXT,
      threat_level TEXT,
      risk_score_delta INTEGER,
      action_taken TEXT,
      details TEXT
    )
  `);

  // 7. Honeytokens Table (Decoy data to catch and trace assaulters)
  db.exec(`
    CREATE TABLE IF NOT EXISTS honeytokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      username TEXT,
      email TEXT,
      credit_card TEXT,
      warning TEXT
    )
  `);

  seedInitialData();
}

function seedInitialData() {
  // Check if products exist
  const count = db.prepare('SELECT COUNT(*) as count FROM products').get().count;
  if (count === 0) {
    const insertProduct = db.prepare(`
      INSERT INTO products (name, category, price, stock, rating, description, image_url)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const p of products) {
      insertProduct.run(p.name, p.category, p.price, p.stock, p.rating, p.description, p.image_url);
    }
  }

  // Check if users exist
  const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get().count;
  if (userCount === 0) {
    const insertUser = db.prepare(`
      INSERT INTO users (username, email, password_hash, role, status, risk_score, category)
      VALUES (?, ?, ?, ?, 'active', 0, 'Benign')
    `);

    const insertProfile = db.prepare(`
      INSERT INTO customer_profiles (user_id, full_name, phone_encrypted, address_encrypted, credit_card_encrypted, credit_card_last4, balance)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    for (const u of demoUsers) {
      const hash = aesx.hashPassword(u.password);
      const res = insertUser.run(u.username, u.email, hash, u.role);
      const userId = res.lastInsertRowid;

      // Encrypt sensitive PII using AESX before writing to SQL
      const phoneEncrypted = aesx.encrypt(u.phone);
      const addressEncrypted = aesx.encrypt(u.address);
      const cardEncrypted = aesx.encrypt(u.creditCard);
      const last4 = u.creditCard.slice(-4);

      insertProfile.run(userId, u.fullName, phoneEncrypted, addressEncrypted, cardEncrypted, last4, u.balance);
    }
  }

  // Check honeytokens
  const honeyCount = db.prepare('SELECT COUNT(*) as count FROM honeytokens').get().count;
  if (honeyCount === 0) {
    const insertHoney = db.prepare(`
      INSERT INTO honeytokens (name, username, email, credit_card, warning)
      VALUES (?, ?, ?, ?, ?)
    `);
    for (const h of honeytokens) {
      insertHoney.run(h.name, h.username, h.email, h.creditCard, h.warning);
    }
  }
}

// Initialize database schema immediately on load
initDatabase();

module.exports = {
  db,
  aesx,
  
  // Safe search using parameterized queries
  searchProductsSafe(query) {
    if (!query) {
      return db.prepare('SELECT * FROM products ORDER BY id ASC').all();
    }
    const sql = `SELECT * FROM products WHERE name LIKE ? OR category LIKE ? OR description LIKE ?`;
    const term = `%${query}%`;
    return db.prepare(sql).all(term, term, term);
  },

  // Raw query executor (used to demonstrate vulnerable execution when DLP bypass is toggled)
  executeRawQuery(sqlQuery) {
    return db.prepare(sqlQuery).all();
  },

  // Log a security incident to DLP audit table
  logIncident({
    userIdentifier = 'anonymous',
    ipAddress = '127.0.0.1',
    endpoint = '/api/unknown',
    requestPayload = '',
    detectionLayer = 'Content Inspection',
    ruleMatched = 'None',
    threatLevel = 'LOW',
    riskScoreDelta = 0,
    actionTaken = 'ALLOWED',
    details = ''
  }) {
    const stmt = db.prepare(`
      INSERT INTO security_incidents (
        user_identifier, ip_address, endpoint, request_payload,
        detection_layer, rule_matched, threat_level, risk_score_delta,
        action_taken, details
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const res = stmt.run(
      userIdentifier,
      ipAddress,
      endpoint,
      typeof requestPayload === 'object' ? JSON.stringify(requestPayload) : String(requestPayload),
      detectionLayer,
      ruleMatched,
      threatLevel,
      riskScoreDelta,
      actionTaken,
      typeof details === 'object' ? JSON.stringify(details) : String(details)
    );
    return res.lastInsertRowid;
  },

  // Fetch recent incidents
  getIncidents(limit = 50) {
    return db.prepare(`
      SELECT * FROM security_incidents
      ORDER BY id DESC
      LIMIT ?
    `).all(limit);
  },

  // Get user by username
  getUserByUsername(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  },

  // Get customer profile with optional decryption
  getUserProfile(userId, decryptData = false) {
    const profile = db.prepare(`
      SELECT u.id, u.username, u.email, u.role, u.status, u.risk_score, u.category, u.created_at,
             cp.full_name, cp.phone_encrypted, cp.address_encrypted, cp.credit_card_encrypted,
             cp.credit_card_last4, cp.balance
      FROM users u
      LEFT JOIN customer_profiles cp ON u.id = cp.user_id
      WHERE u.id = ?
    `).get(userId);

    if (!profile) return null;

    if (decryptData) {
      try {
        profile.phone = aesx.decrypt(profile.phone_encrypted);
        profile.address = aesx.decrypt(profile.address_encrypted);
        profile.credit_card = aesx.decrypt(profile.credit_card_encrypted);
      } catch (err) {
        profile.decryption_error = err.message;
      }
    }

    return profile;
  },

  // Get all customer profiles for AESX Vault Inspector (comparison view)
  getAllVaultProfiles() {
    const rows = db.prepare(`
      SELECT u.id as user_id, u.username, u.email, u.category, u.status,
             cp.full_name, cp.phone_encrypted, cp.address_encrypted, cp.credit_card_encrypted, cp.credit_card_last4
      FROM users u
      LEFT JOIN customer_profiles cp ON u.id = cp.user_id
    `).all();

    return rows.map(r => ({
      userId: r.user_id,
      username: r.username,
      email: r.email,
      category: r.category,
      status: r.status,
      fullName: r.full_name,
      creditCardLast4: r.credit_card_last4,
      encrypted: {
        phone: r.phone_encrypted,
        address: r.address_encrypted,
        creditCard: r.credit_card_encrypted
      },
      decrypted: {
        phone: aesx.decrypt(r.phone_encrypted),
        address: aesx.decrypt(r.address_encrypted),
        creditCard: aesx.maskValue(aesx.decrypt(r.credit_card_encrypted), 'card')
      }
    }));
  },

  // Update user risk & status
  updateUserRisk(userId, riskScore, category, status) {
    return db.prepare(`
      UPDATE users
      SET risk_score = ?, category = ?, status = ?
      WHERE id = ?
    `).run(riskScore, category, status, userId);
  },

  // Reset user risk & status
  resetUserStatus(userId) {
    return db.prepare(`
      UPDATE users
      SET risk_score = 0, category = 'Benign', status = 'active'
      WHERE id = ?
    `).run(userId);
  },

  // Record an order
  createOrder(userId, customerName, totalAmount, items, shippingAddress) {
    const shippingEncrypted = aesx.encrypt(shippingAddress);
    const stmt = db.prepare(`
      INSERT INTO orders (user_id, customer_name, total_amount, items_json, shipping_encrypted)
      VALUES (?, ?, ?, ?, ?)
    `);
    const res = stmt.run(userId, customerName, totalAmount, JSON.stringify(items), shippingEncrypted);
    return res.lastInsertRowid;
  },

  // Store user message
  saveMessage(userId, username, messageText, inspectionStatus, threatLevel, leakIndicators, actionTaken) {
    const stmt = db.prepare(`
      INSERT INTO user_messages (user_id, username, message_text, inspection_status, threat_level, leak_indicators, action_taken)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    return stmt.run(userId, username, messageText, inspectionStatus, threatLevel, leakIndicators, actionTaken);
  },

  // Get user messages
  getMessages(limit = 20) {
    return db.prepare('SELECT * FROM user_messages ORDER BY id DESC LIMIT ?').all(limit);
  },

  // Get Honeytoken decoys
  getHoneytokens() {
    return db.prepare('SELECT * FROM honeytokens').all();
  }
};
