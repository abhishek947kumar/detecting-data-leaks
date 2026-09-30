/**
 * DLP Content Inspection Engine
 * Inspects payloads, queries, and user messages for SQL Injection attacks,
 * PII/Financial leaks (Credit cards, SSNs, API keys), and Keystroke/Ransomware payloads.
 */

// Luhn Algorithm to validate credit card numbers (prevents false positives)
function validateLuhn(numberStr) {
  const digits = numberStr.replace(/\D/g, '');
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

// Rules Repository
const RULES = [
  // --- SQL Injection Detection Rules ---
  {
    id: 'SQLI_TAUTOLOGY',
    name: 'SQL Tautology / Boolean Bypass',
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    riskScore: 40,
    regex: /(?:'|\b)\s*(?:OR|AND)\s+['"]?([0-9a-z]+)['"]?\s*=\s*['"]?\1['"]?|'\s*OR\s*'[^']+'\s*=\s*'[^']+/i,
    description: 'Detection of tautological expressions designed to bypass SQL authentication or filter logic (e.g., OR 1=1).'
  },
  {
    id: 'SQLI_UNION',
    name: 'SQL Union-Based Exfiltration',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    riskScore: 50,
    regex: /\bUNION\s+(?:ALL\s+)?SELECT\b/i,
    description: 'Attempts to append unauthorized SELECT statements to extract sensitive database rows.'
  },
  {
    id: 'SQLI_SCHEMA_SNOOPING',
    name: 'SQL Metadata / Schema Harvesting',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    riskScore: 45,
    regex: /\b(?:sqlite_master|information_schema|sys\.tables|sys\.columns|pg_tables|all_tables)\b/i,
    description: 'Attempts to inspect internal database catalogues, tables, or column structures.'
  },
  {
    id: 'SQLI_COMMENT_EVASION',
    name: 'SQL Comment / Truncation Evasion',
    category: 'SQL_INJECTION',
    severity: 'MEDIUM',
    riskScore: 25,
    regex: /(?:--|\/\*|\*\/|#\s*$|--\s+-+)/,
    description: 'SQL inline comment delimiters used to neutralize trailing query syntax.'
  },
  {
    id: 'SQLI_STACKED_DDL',
    name: 'SQL Stacked Destruction / DDL Injection',
    category: 'SQL_INJECTION',
    severity: 'CRITICAL',
    riskScore: 55,
    regex: /;\s*(?:DROP|TRUNCATE|DELETE\s+FROM|ALTER|CREATE|UPDATE\s+\w+\s+SET)\b/i,
    description: 'Stacked or chained SQL commands intended to drop, alter, or manipulate database records.'
  },
  {
    id: 'SQLI_TIME_BLIND',
    name: 'Time-Based / Blind SQL Injection Function',
    category: 'SQL_INJECTION',
    severity: 'HIGH',
    riskScore: 35,
    regex: /\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|randomblob)\s*\(/i,
    description: 'Time delay or CPU-intensive functions used in blind SQL injection inference.'
  },

  // --- Data Leak / Exfiltration Rules ---
  {
    id: 'LEAK_CREDIT_CARD',
    name: 'Credit Card Number Exfiltration Pattern',
    category: 'PII_LEAK',
    severity: 'CRITICAL',
    riskScore: 45,
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b|\b(?:\d{4}[ -]?){3}\d{4}\b/,
    customValidator: validateLuhn,
    description: 'Unencrypted credit card number (Visa, Mastercard, Amex, Discover) detected in text payload.'
  },
  {
    id: 'LEAK_SSN',
    name: 'Social Security Number (SSN) Leak',
    category: 'PII_LEAK',
    severity: 'HIGH',
    riskScore: 35,
    regex: /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/,
    description: 'Unprotected Social Security Number detected in outgoing communication or query.'
  },
  {
    id: 'LEAK_API_KEY',
    name: 'Private Key / API Secret Exfiltration',
    category: 'PII_LEAK',
    severity: 'HIGH',
    riskScore: 40,
    regex: /\b(?:AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,40}|Bearer\s+ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}|-----BEGIN\s+PRIVATE\s+KEY-----)\b/,
    description: 'High-entropy cloud credentials, JWT tokens, or private RSA keys identified in message.'
  },
  {
    id: 'LEAK_PASSWORD_COMBO',
    name: 'Credential Dump / Combos Leak',
    category: 'PII_LEAK',
    severity: 'MEDIUM',
    riskScore: 30,
    regex: /(?:password|passwd|pwd)\s*[:=]\s*[^\s,;]{4,}/i,
    description: 'Plaintext passwords or account credential pairings detected in transmission.'
  },

  // --- Keystroke Theft & Malicious Code Injection ---
  {
    id: 'KEYSTROKE_THEFT_INJECTION',
    name: 'Keystroke Logger / Key-Sniffing Script Injection',
    category: 'KEYSTROKE_THEFT',
    severity: 'CRITICAL',
    riskScore: 50,
    regex: /(?:addEventListener\s*\(\s*['"](?:keypress|keydown|keyup)['"]|document\.(?:onkeydown|onkeypress)|keylogger|logKeystroke)/i,
    description: 'Malicious JavaScript payload intended to record and exfiltrate user keystrokes.'
  },
  {
    id: 'RANSOMWARE_SHELL_PAYLOAD',
    name: 'Ransomware / Command Execution Artifact',
    category: 'RANSOMWARE',
    severity: 'CRITICAL',
    riskScore: 55,
    regex: /(?:powershell\s+-enc|cmd\.exe\s+\/c|eval\s*\(\s*base64_decode|certutil\s+-urlcache|WScript\.Shell)/i,
    description: 'System command execution or ransomware loader script detected in uploaded message.'
  }
];

/**
 * Inspect a given text payload or query
 * @param {string} payload - Raw text, query or message
 * @param {string} contextSource - e.g., 'SQL_QUERY', 'CHAT_MESSAGE', 'SEARCH_INPUT', 'AUTH_INPUT'
 * @returns {object} Detailed inspection report
 */
function inspectContent(payload, contextSource = 'GENERAL') {
  if (typeof payload !== 'string' || !payload.trim()) {
    return {
      isThreat: false,
      threatLevel: 'CLEAN',
      score: 0,
      matches: [],
      sanitized: payload,
      contextSource
    };
  }

  const matches = [];
  let totalScore = 0;

  for (const rule of RULES) {
    const regexMatch = payload.match(rule.regex);
    if (regexMatch) {
      const matchedSnippet = regexMatch[0];
      
      // If custom validator exists (e.g., Luhn test for credit cards)
      if (rule.customValidator) {
        if (!rule.customValidator(matchedSnippet)) {
          continue; // False positive skipped
        }
      }

      totalScore += rule.riskScore;
      matches.push({
        ruleId: rule.id,
        ruleName: rule.name,
        category: rule.category,
        severity: rule.severity,
        riskScore: rule.riskScore,
        matchedToken: matchedSnippet.length > 50 ? matchedSnippet.substring(0, 47) + '...' : matchedSnippet,
        description: rule.description
      });
    }
  }

  // Determine Overall Threat Level
  let threatLevel = 'CLEAN';
  let recommendedAction = 'ALLOW';

  if (totalScore >= 70 || matches.some(m => m.severity === 'CRITICAL')) {
    threatLevel = 'CRITICAL';
    recommendedAction = 'RESTRICT_USER';
  } else if (totalScore >= 40 || matches.some(m => m.severity === 'HIGH')) {
    threatLevel = 'HIGH';
    recommendedAction = 'QUARANTINE_OR_HONEYTOKEN';
  } else if (totalScore >= 20 || matches.some(m => m.severity === 'MEDIUM')) {
    threatLevel = 'MEDIUM';
    recommendedAction = 'SANITIZE_AND_WARN';
  } else if (totalScore > 0) {
    threatLevel = 'LOW';
    recommendedAction = 'LOG_AND_MONITOR';
  }

  // Sanitized version (neutralize dangerous SQL characters and script tags)
  let sanitized = payload
    .replace(/--/g, '')
    .replace(/;/g, '')
    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '[REMOVED_SCRIPT]')
    .replace(/(UNION\s+SELECT|DROP\s+TABLE|OR\s+1=1)/gi, '[BLOCKED_SQL_EXPR]');

  return {
    isThreat: matches.length > 0,
    threatLevel,
    score: Math.min(totalScore, 100),
    matchCount: matches.length,
    matches,
    sanitized,
    recommendedAction,
    contextSource,
    timestamp: new Date().toISOString()
  };
}

/**
 * Return all active rules for the SOC view
 */
function getActiveRules() {
  return RULES.map(r => ({
    id: r.id,
    name: r.name,
    category: r.category,
    severity: r.severity,
    riskScore: r.riskScore,
    description: r.description
  }));
}

module.exports = {
  inspectContent,
  getActiveRules,
  validateLuhn
};
