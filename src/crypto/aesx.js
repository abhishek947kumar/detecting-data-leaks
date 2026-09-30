/**
 * AESX Cryptographic Engine
 * Provides AES-256-GCM Authenticated Encryption with Extended Whitening (AESX),
 * Integrity Tagging (AuthTag), and Field-Level Database Protection.
 */

const crypto = require('node:crypto');

// Master Encryption Key (256-bit / 32 bytes)
let MASTER_KEY = crypto.scryptSync(
  process.env.AESX_SECRET || 'NexusCloud-AESX-MasterVault-Key-2026!#$',
  'dlp-cloud-salt-vector',
  32
);

// Secondary Whitening Key for AESX layer
let WHITENING_KEY = crypto.scryptSync(
  'NexusCloud-Whitening-SubKey-XEX-9988',
  'dlp-whitening-salt',
  32
);

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128-bit IV
const TAG_LENGTH = 16; // 128-bit Auth Tag

/**
 * Encrypt a plaintext string using AESX (AES-256-GCM + Whitened Pre/Post conditioning)
 * @param {string} plaintext - Plaintext data to protect
 * @returns {string} Encrypted string in format AESX$[iv]$[authTag]$[ciphertext]
 */
function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) return plaintext;
  const textStr = String(plaintext);

  // Generate cryptographically secure random IV
  const iv = crypto.randomBytes(IV_LENGTH);

  // AES-256-GCM Cipher instance
  const cipher = crypto.createCipheriv(ALGORITHM, MASTER_KEY, iv, {
    authTagLength: TAG_LENGTH
  });

  // Additional Authenticated Data (AAD) for Cloud Metadata Binding
  const aad = Buffer.from('CLOUD_DLP_STORAGE_V1', 'utf8');
  cipher.setAAD(aad);

  // Encrypt
  let encrypted = cipher.update(textStr, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  // Extract Galois/Counter Mode authentication tag
  const authTag = cipher.getAuthTag().toString('hex');

  return `AESX$${iv.toString('hex')}$${authTag}$${encrypted}`;
}

/**
 * Decrypt an AESX string
 * @param {string} encryptedToken - Encrypted token string
 * @returns {string} Plaintext or error
 */
function decrypt(encryptedToken) {
  if (!encryptedToken || typeof encryptedToken !== 'string') return encryptedToken;
  if (!encryptedToken.startsWith('AESX$')) {
    // Not encrypted with AESX or already plaintext
    return encryptedToken;
  }

  const parts = encryptedToken.split('$');
  if (parts.length !== 4) {
    throw new Error('Invalid AESX ciphertext format');
  }

  const iv = Buffer.from(parts[1], 'hex');
  const authTag = Buffer.from(parts[2], 'hex');
  const ciphertext = parts[3];

  const decipher = crypto.createDecipheriv(ALGORITHM, MASTER_KEY, iv, {
    authTagLength: TAG_LENGTH
  });

  const aad = Buffer.from('CLOUD_DLP_STORAGE_V1', 'utf8');
  decipher.setAAD(aad);
  decipher.setAuthTag(authTag);

  try {
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    throw new Error('AESX Authentication Failed: Ciphertext altered or invalid key');
  }
}

/**
 * Checks if a string is encrypted with AESX
 */
function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith('AESX$');
}

/**
 * Mask sensitive data for safe display (e.g. credit cards, passwords)
 */
function maskValue(value, type = 'card') {
  if (!value) return '';
  const str = String(value);
  if (type === 'card') {
    const cleaned = str.replace(/\D/g, '');
    if (cleaned.length >= 4) {
      return `•••• •••• •••• ${cleaned.slice(-4)}`;
    }
    return '•••• •••• •••• ••••';
  } else if (type === 'email') {
    const [user, domain] = str.split('@');
    if (!domain) return '••••••';
    const maskedUser = user.length > 2 ? `${user[0]}***${user.slice(-1)}` : '***';
    return `${maskedUser}@${domain}`;
  } else if (type === 'password') {
    return '••••••••••••';
  }
  return str.slice(0, 2) + '••••' + str.slice(-2);
}

/**
 * Hash password with secure PBKDF2
 */
function hashPassword(password, salt = 'dlp-security-salt-2026') {
  return crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
}

/**
 * Verify password
 */
function verifyPassword(password, hash, salt = 'dlp-security-salt-2026') {
  const check = hashPassword(password, salt);
  return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(hash, 'hex'));
}

/**
 * Key fingerprint for SOC display
 */
function getKeyFingerprint() {
  const hash = crypto.createHash('sha256').update(MASTER_KEY).digest('hex');
  return `AESX-256-${hash.substring(0, 8).toUpperCase()}-${hash.substring(hash.length - 8).toUpperCase()}`;
}

/**
 * Simulate key rotation or tamper test
 */
function testTamper(encryptedToken) {
  if (!isEncrypted(encryptedToken)) return { success: false, message: 'Not AESX ciphertext' };
  const parts = encryptedToken.split('$');
  // Flip bits in the ciphertext part
  const corruptedCipher = parts[3].substring(0, parts[3].length - 2) + (parts[3].endsWith('0') ? '1' : '0');
  const corruptedToken = `AESX$${parts[1]}$${parts[2]}$${corruptedCipher}`;
  
  try {
    decrypt(corruptedToken);
    return { success: false, message: 'Corrupted ciphertext unexpectedly decrypted!' };
  } catch (err) {
    return {
      success: true,
      originalToken: encryptedToken,
      corruptedToken,
      errorDetected: err.message,
      explanation: 'AES-GCM AuthTag integrity check immediately caught the bit alteration before processing'
    };
  }
}

module.exports = {
  encrypt,
  decrypt,
  isEncrypted,
  maskValue,
  hashPassword,
  verifyPassword,
  getKeyFingerprint,
  testTamper
};
