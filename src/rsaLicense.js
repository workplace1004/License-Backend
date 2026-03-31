import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { canonicalStringify } from './canonicalStringify.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_PRIVATE_KEY_PATH = path.join(__dirname, '..', 'keys', 'license-private.pem');
const DEFAULT_PUBLIC_KEY_PATH = path.join(__dirname, '..', 'keys', 'license-public.pem');

let _privateKey = null;

function loadPrivateKeyPem() {
  const inline = process.env.LICENSE_RSA_PRIVATE_KEY_PEM;
  if (inline && String(inline).trim()) {
    return String(inline).replace(/\\n/g, '\n');
  }
  const envPath = process.env.LICENSE_RSA_PRIVATE_KEY_PATH;
  if (envPath && fs.existsSync(envPath)) {
    return fs.readFileSync(envPath, 'utf8');
  }
  if (fs.existsSync(DEFAULT_PRIVATE_KEY_PATH)) {
    return fs.readFileSync(DEFAULT_PRIVATE_KEY_PATH, 'utf8');
  }
  return null;
}

export function ensurePrivateKeyLoaded() {
  if (_privateKey !== null) return _privateKey;
  const pem = loadPrivateKeyPem();
  _privateKey = pem;
  return pem;
}

/**
 * @param {object} data — license payload (plain object)
 * @returns {string} base64 signature
 */
export function signLicense(data) {
  const pem = ensurePrivateKeyLoaded();
  if (!pem) {
    throw new Error('LICENSE_RSA_PRIVATE_KEY_PATH or LICENSE_RSA_PRIVATE_KEY_PEM is not configured');
  }
  const payload = canonicalStringify(data);
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(payload);
  sign.end();
  return sign.sign(pem, 'base64');
}

export function verifyLicense(data, signatureBase64) {
  const inline = process.env.LICENSE_RSA_PUBLIC_KEY_PEM;
  const envPubPath = process.env.LICENSE_RSA_PUBLIC_KEY_PATH;
  let pubPem = inline ? String(inline).replace(/\\n/g, '\n') : null;
  if (!pubPem && envPubPath && fs.existsSync(envPubPath)) {
    pubPem = fs.readFileSync(envPubPath, 'utf8');
  }
  if (!pubPem && fs.existsSync(DEFAULT_PUBLIC_KEY_PATH)) {
    pubPem = fs.readFileSync(DEFAULT_PUBLIC_KEY_PATH, 'utf8');
  }
  if (!pubPem) return false;
  try {
    const payload = canonicalStringify(data);
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(payload);
    verify.end();
    return verify.verify(pubPem, signatureBase64, 'base64');
  } catch {
    return false;
  }
}
