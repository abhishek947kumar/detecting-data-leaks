# 🔒 Security Policy

## Supported Versions

Security updates and patches are actively maintained for the latest release:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## Reporting a Vulnerability

If you discover a security vulnerability, novel bypass for the DLP Content Inspector, or flaw in the AESX cryptographic implementation, please **do NOT report it via public GitHub issues**.

Instead, send a responsible disclosure report to the security maintainers with:
- Summary of the vulnerability or bypass technique
- Proof of Concept (PoC) payload or steps to reproduce
- Estimated impact and severity

Security disclosures will be acknowledged within **48 hours**, and a mitigation or patch will be prioritized.

---

## 🛡️ Threat Model & Cryptographic Guarantees

1. **Storage Security (AESX):**
   - Cipher: AES-256-GCM authenticated encryption.
   - IVs: 128-bit cryptographically secure pseudorandom numbers generated per-field.
   - Integrity: 128-bit authentication tags ensure ciphertext tamper resistance.
2. **Gateway Defense:**
   - Content inspection regex matching combined with algorithmic validators (Luhn).
   - Contextual sliding-window anomaly detection for brute force and velocity bursts.
3. **Decoy Isolation:**
   - Honeypot tokens contain purely synthetic data and do not touch real customer profiles.
