# 🛡️ Detecting Data Leaks Using SQL & Cloud DLP Architecture

> **An Enterprise-Grade Cloud Security & Data Loss Prevention (DLP) Platform with AESX Authenticated Field Encryption, Real-Time SQL Injection Detection, Contextual Behavioral Analytics, and User Threat Categorization.**

---

## 📌 Executive Summary & Context

Data leaks have surged exponentially in the post-pandemic digital landscape, creating severe financial and psychological harm for innocent users who rely on daily web services, e-commerce stores, and cloud portals. Whether driven by credential harvesting via keystroke loggers, SQL injection exploits that siphon database records, or unauthorized data exfiltration through compromised channels, modern vulnerabilities require multi-layered defense.

This system combines **Dual-Engine Inspection (Content Inspection & Contextual Analysis)** with **AESX Cryptography** to defend e-commerce platforms and user data against sophisticated attacks:

```
                                 [ Incoming Request / Message / Query ]
                                                   │
                                                   ▼
                     ┌───────────────────────────────────────────────────────────┐
                     │                   CLOUD DLP SHIELD GATEWAY                 │
                     ├─────────────────────────────┬─────────────────────────────┤
                     │   LAYER 1: CONTENT ENGINE   │  LAYER 2: CONTEXTUAL ENGINE │
                     │  - SQL Injection Detection  │  - User Behavioral Profile  │
                     │  - Luhn-Verified CC Leaks   │  - Query Velocity / Bursts  │
                     │  - SSN, API Keys, Passwords │  - Sub-Human Typing Cadence │
                     │  - Keystroke Logger Scripts │  - Error Rate Spike (Fuzz)  │
                     └──────────────┬──────────────┴──────────────┬──────────────┘
                                    │                             │
                                    └──────────────┬──────────────┘
                                                   │ Dynamic Risk Score (0 - 100)
                                                   ▼
                     ┌───────────────────────────────────────────────────────────┐
                     │            INTELLIGENT RESTRICTION & CATEGORIZATION        │
                     │   • Benign (Score < 30)      ──► Permitted Normal Access  │
                     │   • Suspicious (Score 30-69) ──► Sanitized & Warned       │
                     │   • Assaulter (Score >= 70)  ──► Quarantined + Honeypot   │
                     └─────────────────────────────┬─────────────────────────────┘
                                                   │
                                                   ▼
                     ┌───────────────────────────────────────────────────────────┐
                     │         AESX CRYPTOGRAPHIC FIELD-LEVEL VAULT (SQLite)     │
                     │     Format: AESX$[128-bit IV]$[128-bit AuthTag]$[Cipher]   │
                     │     Authenticated Encryption: Bit Tampering Rejected      │
                     └───────────────────────────────────────────────────────────┘
```

---

## 🔐 Key Architectural Pillars

### 1. AESX Authenticated Cryptographic Engine
- **Cipher Algorithm:** AES-256-GCM (Galois/Counter Mode) with 128-bit initialization vectors and 128-bit authentication integrity tags (`authTag`).
- **Additional Authenticated Data (AAD):** Cryptographically bound to cloud storage metadata to prevent replay attacks across environments.
- **Field-Level Encryption (FLE):** Customer sensitive records (`credit_card_encrypted`, `address_encrypted`, `phone_encrypted`) are transformed into `AESX$[iv]$[authTag]$[ciphertext]` before touching SQL storage.
- **Tamper Resistance:** Even if an attacker gains raw database access and alters ciphertext bits, the AES-GCM authentication tag calculation immediately fails on decryption, preventing corrupted or manipulated data from being processed.

### 2. Layer 1: DLP Content Inspection Engine
- **SQL Injection Detection:**
  * **Tautology & Boolean Bypasses:** `' OR '1'='1`, `admin' --`, `OR 1=1`
  * **Union-Based Harvesting:** `UNION SELECT`, `UNION ALL SELECT`, schema extraction
  * **System Catalog Snooping:** `sqlite_master`, `information_schema`, `sys.tables`
  * **Stacked DDL Destruction:** `; DROP TABLE`, `; DELETE FROM`, `; UPDATE`
  * **Blind & Time-Based Inferences:** `sleep()`, `benchmark()`, `randomblob()`
- **Sensitive Data Exfiltration Inspection:**
  * **Credit Card Numbers:** Checked via regex patterns for Visa, Mastercard, Amex, Discover and validated against the mathematical **Luhn Algorithm Checksum** to eradicate false positives.
  * **Social Security Numbers (SSN):** Matches format `\d{3}-\d{2}-\d{4}`.
  * **High-Entropy Credentials:** Detects leaked JWT tokens (`Bearer ey...`), AWS Access Keys (`AKIA...`), and private RSA keys.
- **Malicious Code & Keystroke Theft Detection:**
  * Identifies script-based keyloggers (`addEventListener('keypress')`, `document.onkeydown`, `fetch('http://.../log?k=' + key)`).
  * Catches ransomware loaders, base64 eval scripts, and encoded PowerShell command strings.

### 3. Layer 2: DLP Contextual Behavioral Analysis
- **User Behavior Analytics (UBA):** Tracks continuous session metrics across a rolling 60-second sliding window.
- **Velocity & Burst Detection:** Flags automated scrapers and bot crawlers firing more than 8 queries in under 60 seconds or rapid sub-second bursts.
- **Typing Cadence & Keystroke Dynamics:** Analyzes the millisecond interval per character. Complex payloads pasted or automated in under 15ms/character are flagged as robotic replay or stolen script injections.
- **Consecutive Error Anomaly:** Detects blind fuzzing when a user triggers multiple database syntax errors in sequence.

### 4. User Threat Categorization & Intelligent Mitigation
- **Benign Users (Risk 0 - 29):** Normal shoppers, unrestricted access.
- **Suspicious Users (Risk 30 - 69):** Issued warning alerts, inputs strictly sanitized, activity monitored closely.
- **Malicious Assaulters (Risk 70 - 100):** Immediately quarantined, accounts locked down, session terminated, and deceptive **Honeypot Decoy Tokens** served to mislead and trace the assaulter without risking real customer data.

---

## 🚀 Quick Start Guide

### Prerequisites
- Node.js **v20+** (v24 recommended; utilizes native `node:sqlite` and `node:crypto`)
- Modern web browser (Chrome, Edge, Firefox, Safari)

### Installation & Launch

1. **Clone or Navigate to the Workspace:**
   ```bash
   cd "d:/Engineering/Detecting Data Leaks"
   ```

2. **Install Dependencies:**
   ```bash
   npm install
   ```

3. **Start the Application:**
   ```bash
   npm start
   ```
   *The server starts on `http://localhost:3000`.*

4. **Run the Automated Security Verification Test:**
   ```bash
   node test_system.js
   ```
   *Runs 22 comprehensive assertions validating SQLi interception, PII leak blocking, keylogger neutralization, and AESX vault integrity.*

---

## 🖥️ Web Interface Walkthrough

Open your browser and navigate to **`http://localhost:3000`**:

### View 1: 🛒 Nexus E-Shop (Customer Platform)
- **Interactive Search Catalog:** Search security products, or click quick-attack chips like `' OR '1'='1` or `' UNION SELECT...` to witness the DLP Shield intercepting SQL injections in real-time.
- **DLP Bypass Switch (Demo Mode):** Toggle between **"DLP Shield Active"** and **"Vulnerable Raw SQL Mode"** to demonstrate the catastrophic impact of unprotected SQL execution versus active DLP interception.
- **Secure Shopping Cart & AESX Checkout:** Add hardware security keys or encrypted SSDs to your cart. Enter credit card credentials to see real-time Luhn validation and AESX encryption preview before database storage.
- **Customer Support Leak Portal:** Type or click chips to test message-based leaks (e.g. credit card dumps, keylogger scripts, or benign inquiries).

### View 2: ⚡ Cloud DLP SOC (Security Operations Center)
- **📊 Live Incident Stream:** Real-time chronological audit table streamed via **Server-Sent Events (SSE)**. Click any incident to open the forensic telemetry breakdown.
- **🧪 Deep Inspection Sandbox:** Interactive terminal to paste custom SQL queries, payloads, or messages and receive immediate AST token parsing, rule matches, and contextual score evaluation.
- **👥 User Threat Categorization Matrix:** Visual Kanban-style view showing users categorized into **Benign**, **Suspicious**, and **Assaulter** with live risk meters and one-click Quarantine/Pardon buttons.
- **🔐 AESX Cryptographic Vault Explorer:** Side-by-side comparison of raw SQLite ciphertexts (`AESX$[iv]$[authTag]$[cipher]`) versus authorized decrypted data, plus an interactive **Simulate Cipher Tampering** test proving AES-GCM integrity rejection.
- **⚡ Attack Simulator:** Five one-click attack triggers:
  1. *Classic Tautology Auth Bypass (`' OR '1'='1 --`)*
  2. *Union-Based Credit Card Exfiltration*
  3. *Outbound PII / Financial Data Dump*
  4. *Keystroke Theft Logger Injection*
  5. *High-Frequency Bot Velocity Probe*

---

## 📂 Repository File Structure

```
d:/Engineering/Detecting Data Leaks/
├── package.json               # Project manifest, scripts, Express dependency
├── server.js                  # Main server, REST API, SSE live stream, and attack routes
├── test_system.js             # Automated 22-assertion end-to-end verification test suite
├── src/
│   ├── crypto/
│   │   └── aesx.js            # AES-256-GCM + Whitening & AuthTag integrity engine
│   ├── db/
│   │   ├── database.js        # Native SQLite engine, AESX field encryption, audit log
│   │   └── seedData.js        # Realistic catalog products, demo users, decoy honeytokens
│   └── dlp/
│       ├── contentInspector.js # SQLi regex AST rules, Luhn algorithm, PII & keylogger rules
│       ├── contextualEngine.js # Behavioral telemetry, burst velocity, risk scoring (0-100)
│       └── dlpCore.js         # Gateway orchestrator, SSE broadcaster, restriction engine
└── public/
    ├── index.html             # Single-page application (Storefront + Cloud SOC views)
    ├── css/
    │   ├── style.css          # Design system, glassmorphic tokens, cyber theme
    │   └── components.css     # KPI cards, incident tables, sandbox terminal, modals
    └── js/
        ├── app.js             # State orchestration, SSE client, notification toasts
        ├── store.js           # E-commerce catalog, search, cart, AESX checkout, chat portal
        ├── soc.js             # SOC dashboard, live incident stream, user categorization
        ├── sandbox.js         # Interactive payload testing terminal
        └── vault.js           # AESX Vault comparison and tamper resistance demo
```

---

## 📡 Core API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/products` | Retrieve all security products from the database |
| `POST` | `/api/products/search` | Search catalog through DLP Content Inspection & Contextual Analysis |
| `POST` | `/api/auth/login` | User login with SQLi authentication bypass protection & typing telemetry |
| `POST` | `/api/checkout` | Process order with AESX field-level encrypted credit card & shipping details |
| `POST` | `/api/messages/send` | Submit customer support inquiry inspected for data leaks and keyloggers |
| `GET` | `/api/dlp/stream` | Server-Sent Events (SSE) live threat telemetry stream |
| `GET` | `/api/dlp/stats` | Executive KPI metrics (inspections, assaulters, blocked leaks, key status) |
| `GET` | `/api/dlp/incidents` | Historical security audit log |
| `GET` | `/api/dlp/users` | User risk scores and categorization directory |
| `POST` | `/api/dlp/users/:id/action` | Admin override: `RESET` risk or `RESTRICT` user |
| `POST` | `/api/dlp/inspect-payload` | Interactive payload analysis sandbox |
| `GET` | `/api/dlp/vault` | Database vault viewer (Ciphertext vs Authorized Decrypted View) |
| `POST` | `/api/dlp/vault/tamper-test` | Test AES-GCM AuthTag tamper resistance by corrupting ciphertext bits |
| `POST` | `/api/dlp/simulate-attack` | Launch pre-configured realistic attack vectors |

---

## 🏆 Project Achievements & Compliance
- **Full Spectrum SQL Injection Neutralization:** Guards against Tautology bypasses, Union extraction, Schema harvesting, Stacked queries, and Blind SQLi.
- **Mathematical Luhn Validation:** Completely eliminates false-positive card leak alerts.
- **Zero-Trust Field Encryption:** Real credit cards and PII never reside as plaintext in SQL storage.
- **Proactive Anomaly Scoring:** Identifies malicious actors before mass data harvesting succeeds.
- **Real-Time SOC Observability:** Instant SSE-powered visibility into threats across the enterprise.
