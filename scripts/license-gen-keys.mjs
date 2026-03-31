/**
 * Generate RSA-2048 key pair for license signing (server private, POS / issuer use public).
 * Usage: npm run license:keys  (from license-server/)
 */
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const keysDir = path.join(__dirname, '..', 'keys');

fs.mkdirSync(keysDir, { recursive: true });

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const privPath = path.join(keysDir, 'license-private.pem');
const pubPath = path.join(keysDir, 'license-public.pem');
fs.writeFileSync(privPath, privateKey, 'utf8');
fs.writeFileSync(pubPath, publicKey, 'utf8');

console.log('Wrote:', privPath);
console.log('Wrote:', pubPath);
console.log('\nDeploy: keep private key on the license-server host only.');
console.log('Set POS frontend VITE_LICENSE_RSA_PUBLIC_KEY_PEM from license-public.pem');
