import crypto from 'crypto';

/** Keep in sync with `frontend/src/lib/posWebLicense.js` (encrypted license file). */
export const LICENSE_FILE_MAGIC = Buffer.from('PRFL', 'ascii');
export const LICENSE_FILE_CRYPTO_VERSION = 1;

export function getLicenseFileEncryptionKeyBuffer() {
  const hex = String(process.env.LICENSE_FILE_ENCRYPTION_KEY || '').trim();
  if (!/^[a-fA-F0-9]{64}$/.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}

/**
 * @param {Buffer} plaintextUtf8
 * @returns {Buffer} MAGIC | v1 | iv(12) | ciphertext | tag(16)
 */
export function encryptLicenseFilePlaintext(plaintextUtf8) {
  const key = getLicenseFileEncryptionKeyBuffer();
  if (!key || key.length !== 32) {
    throw new Error('LICENSE_FILE_ENCRYPTION_KEY must be 64 hex chars (32 bytes)');
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintextUtf8), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([LICENSE_FILE_MAGIC, Buffer.from([LICENSE_FILE_CRYPTO_VERSION]), iv, enc, tag]);
}
