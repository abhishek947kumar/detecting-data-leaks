# 🤝 Contributing to DLP Cloud Shield

Thank you for your interest in contributing to the **Detecting Data Leaks Using SQL & Cloud DLP Architecture** project!

We welcome contributions from cybersecurity researchers, software engineers, and open-source enthusiasts. Follow these guidelines to ensure a smooth collaboration.

---

## 🛠️ Development Setup

1. **Fork & Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/detecting-data-leaks.git
   cd detecting-data-leaks
   ```

2. **Verify Node.js Version:**
   Node.js **v20+** or **v24** is required (as the project uses native `node:sqlite` and `node:crypto`).
   ```bash
   node -v
   ```

3. **Install Dependencies:**
   ```bash
   npm install
   ```

4. **Copy Environment Variables:**
   ```bash
   cp .env.example .env
   ```

5. **Start Development Server with Hot-Reloading:**
   ```bash
   npm run dev
   ```
   Open `http://localhost:3000` in your browser.

---

## 🧪 Running Tests

Before submitting any code changes, ensure all automated tests pass:

```bash
npm test
```

This runs `test_system.js`, asserting:
- REST API endpoint functionality
- SQL Injection detection (Tautology, Union-based, Schema harvesting)
- Luhn credit card validation and SSN data leak interception
- Script-based keylogger injection neutralization
- AESX field-level encryption format and tamper resistance
- SOC audit logging and incident triage

---

## 🛡️ Adding New DLP Rules

DLP detection rules reside in [`src/dlp/contentInspector.js`](src/dlp/contentInspector.js).

When creating a new rule:
1. Define a unique `id` (e.g. `SQLI_NEW_VECTOR` or `LEAK_PASSPORT`).
2. Provide a descriptive `name` and appropriate `category` (`SQL_INJECTION`, `PII_LEAK`, `KEYSTROKE_THEFT`, `RANSOMWARE`).
3. Set an accurate `severity` (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) and `riskScore` (10–55).
4. Provide a robust regular expression `regex`.
5. *(Optional)* Add a `customValidator(matchString)` function (such as Luhn algorithm for numbers or entropy verification).
6. Add unit test assertions in `test_system.js`.

---

## 📬 Pull Request (PR) Workflow

1. Create a descriptive feature branch:
   ```bash
   git checkout -b feature/new-dlp-rule
   ```
2. Commit changes with clear, concise messages:
   ```bash
   git commit -m "feat(dlp): add detection rule for blind time-based SQLi"
   ```
3. Push to your fork:
   ```bash
   git push origin feature/new-dlp-rule
   ```
4. Open a Pull Request against the `main` branch with details on what was added/fixed.
