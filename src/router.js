import express from 'express';
import { signLicense } from './rsaLicense.js';
import { generateLicenseKeySegments } from './generateLicenseKey.js';
import { encryptLicenseFilePlaintext, getLicenseFileEncryptionKeyBuffer } from './licenseFileCrypto.js';

const POS_LICENSE_FILE_FORMAT = 'pos-restaurant-license';
const POS_LICENSE_FILE_VERSION = 1;

function defaultValidityDays() {
  const n = Number(process.env.LICENSE_DEFAULT_VALIDITY_DAYS || 365);
  return Number.isFinite(n) && n > 0 ? n : 365;
}

function licensePayloadFromRow(row) {
  return {
    licenseKey: row.licenseKey,
    deviceFingerprint: row.deviceFingerprint,
    email: row.email,
    expiresAt: row.expiresAt.toISOString()
  };
}

function parseBirthdayInput(raw) {
  const t = String(raw || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(t)) return null;
  const d = new Date(`${t}T12:00:00.000Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Same rules as issuer UI: formatting chars + 7–15 digits. */
function validatePhoneInput(raw) {
  const t = String(raw || '').trim();
  if (!t) {
    return { ok: false, message: 'Phone number is required.' };
  }
  if (!/^[\d\s\-+().]+$/.test(t)) {
    return {
      ok: false,
      message: 'Phone number can only include digits, spaces, +, -, parentheses, and periods.'
    };
  }
  const digits = t.replace(/\D/g, '');
  if (digits.length < 7) {
    return { ok: false, message: 'Phone number must include at least 7 digits.' };
  }
  if (digits.length > 15) {
    return { ok: false, message: 'Phone number cannot exceed 15 digits.' };
  }
  return { ok: true };
}

/**
 * @param {import('@prisma/client').PrismaClient} prisma
 */
export function createLicenseRouter(prisma) {
  const router = express.Router();

  router.post('/create', async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      if (!email || !email.includes('@')) {
        return res.status(400).json({ ok: false, error: 'invalid_email', message: 'Valid email is required.' });
      }

      const fullName = String(req.body?.fullName || '').trim();
      const phone = String(req.body?.phone || '').trim();
      const address = String(req.body?.address || '').trim();
      const birthdayDate = parseBirthdayInput(req.body?.birthday);
      if (!fullName) {
        return res.status(400).json({ ok: false, error: 'invalid_full_name', message: 'Full name is required.' });
      }
      const phoneCheck = validatePhoneInput(phone);
      if (!phoneCheck.ok) {
        return res.status(400).json({ ok: false, error: 'invalid_phone', message: phoneCheck.message });
      }
      if (!address) {
        return res.status(400).json({ ok: false, error: 'invalid_address', message: 'Address is required.' });
      }
      if (!birthdayDate) {
        return res.status(400).json({
          ok: false,
          error: 'invalid_birthday',
          message: 'Valid birthday (YYYY-MM-DD) is required.'
        });
      }

      let issuedForDevice = String(req.body?.deviceFingerprint || '').trim().toLowerCase();
      if (issuedForDevice && !/^[a-f0-9]{64}$/.test(issuedForDevice)) {
        return res.status(400).json({
          ok: false,
          error: 'invalid_fingerprint',
          message: 'deviceFingerprint must be a 64-character hex string (SHA-256) from the POS device screen.'
        });
      }

      let licenseKey = '';
      for (let attempt = 0; attempt < 32; attempt += 1) {
        licenseKey = generateLicenseKeySegments();
        const exists = await prisma.license.findUnique({ where: { licenseKey } });
        if (!exists) break;
        licenseKey = '';
      }
      if (!licenseKey) {
        return res.status(500).json({ ok: false, error: 'key_generation_failed' });
      }

      const days = defaultValidityDays();
      const expiresAt = new Date();
      expiresAt.setUTCDate(expiresAt.getUTCDate() + days);

      const created = await prisma.license.create({
        data: {
          licenseKey,
          email,
          fullName,
          phone,
          address,
          birthday: birthdayDate,
          expiresAt,
          ...(issuedForDevice ? { deviceFingerprint: issuedForDevice } : {})
        }
      });

      if (!getLicenseFileEncryptionKeyBuffer()) {
        return res.status(500).json({
          ok: false,
          error: 'license_file_crypto_misconfigured',
          message: 'Set LICENSE_FILE_ENCRYPTION_KEY (64 hex chars) on the license server.'
        });
      }

      const licensePayload = licensePayloadFromRow(created);
      let signature;
      try {
        signature = signLicense(licensePayload);
      } catch (signErr) {
        console.error('[license/create] sign', signErr);
        return res.status(500).json({
          ok: false,
          error: 'signing_misconfigured',
          message: 'RSA license signing is not configured on this server.'
        });
      }

      const birthdayIso = created.birthday ? created.birthday.toISOString().slice(0, 10) : '';
      const filePayload = {
        format: POS_LICENSE_FILE_FORMAT,
        version: POS_LICENSE_FILE_VERSION,
        licenseKey: created.licenseKey,
        email: created.email,
        expiresAt: created.expiresAt.toISOString(),
        ...(created.deviceFingerprint ? { deviceFingerprint: created.deviceFingerprint } : {}),
        issuedAt: new Date().toISOString(),
        license: licensePayload,
        signature,
        customer: {
          fullName: created.fullName,
          phone: created.phone,
          address: created.address,
          birthday: birthdayIso
        }
      };
      const encrypted = encryptLicenseFilePlaintext(Buffer.from(JSON.stringify(filePayload), 'utf8'));

      return res.json({
        ok: true,
        licenseKey,
        email,
        expiresAt: expiresAt.toISOString(),
        licenseFileBase64: encrypted.toString('base64'),
        ...(issuedForDevice ? { deviceFingerprint: issuedForDevice } : {})
      });
    } catch (e) {
      console.error('[license/create]', e);
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  router.post('/activate', async (req, res) => {
    try {
      const licenseKey = normalizeKey(req.body?.licenseKey);
      const deviceFingerprint = String(req.body?.deviceFingerprint || '')
        .trim()
        .toLowerCase();
      if (!licenseKey) {
        return res.status(400).json({ ok: false, error: 'invalid_key', message: 'License key is required.' });
      }
      if (!deviceFingerprint) {
        return res.status(400).json({ ok: false, error: 'invalid_fingerprint', message: 'Device fingerprint is required.' });
      }

      const row = await prisma.license.findUnique({ where: { licenseKey } });
      if (!row) {
        return res.status(404).json({ ok: false, error: 'not_found', message: 'Invalid license key.' });
      }
      if (row.expiresAt.getTime() < Date.now()) {
        return res.status(400).json({ ok: false, error: 'expired', message: 'This license has expired.' });
      }

      const rowFp = row.deviceFingerprint ? row.deviceFingerprint.toLowerCase() : null;

      if (!row.isActivated) {
        if (rowFp && rowFp !== deviceFingerprint) {
          return res.status(403).json({
            ok: false,
            error: 'device_mismatch',
            message: 'This license was issued for another device.'
          });
        }
        const updated = await prisma.license.update({
          where: { id: row.id },
          data: rowFp ? { isActivated: true } : { isActivated: true, deviceFingerprint }
        });
        const payload = licensePayloadFromRow(updated);
        const signature = signLicense(payload);
        return res.json({ ok: true, license: payload, signature });
      }

      if (rowFp !== deviceFingerprint) {
        return res.status(403).json({
          ok: false,
          error: 'device_mismatch',
          message: 'This license is already activated on another device.'
        });
      }

      const payload = licensePayloadFromRow(row);
      const signature = signLicense(payload);
      return res.json({ ok: true, license: payload, signature });
    } catch (e) {
      console.error('[license/activate]', e);
      if (e.message?.includes('LICENSE_RSA')) {
        return res.status(500).json({ ok: false, error: 'signing_misconfigured', message: 'Server license signing is not configured.' });
      }
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  router.post('/validate', async (req, res) => {
    try {
      const licenseKey = normalizeKey(req.body?.licenseKey);
      const deviceFingerprint = String(req.body?.deviceFingerprint || '')
        .trim()
        .toLowerCase();
      if (!licenseKey || !deviceFingerprint) {
        return res.status(400).json({ ok: false, error: 'bad_request' });
      }

      const row = await prisma.license.findUnique({ where: { licenseKey } });
      if (!row || !row.isActivated) {
        return res.status(404).json({ ok: false, error: 'not_found', message: 'License not found or not activated.' });
      }
      const rowFp = row.deviceFingerprint ? row.deviceFingerprint.toLowerCase() : '';
      if (rowFp !== deviceFingerprint) {
        return res.status(403).json({ ok: false, error: 'device_mismatch', message: 'This license is bound to another device.' });
      }
      if (row.expiresAt.getTime() < Date.now()) {
        return res.status(400).json({ ok: false, error: 'expired', message: 'This license has expired.' });
      }

      const payload = licensePayloadFromRow(row);
      const signature = signLicense(payload);
      return res.json({ ok: true, license: payload, signature });
    } catch (e) {
      console.error('[license/validate]', e);
      if (e.message?.includes('LICENSE_RSA')) {
        return res.status(500).json({ ok: false, error: 'signing_misconfigured' });
      }
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  return router;
}

function normalizeKey(raw) {
  const alnum = String(raw || '')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
  if (alnum.length !== 12) return '';
  return `${alnum.slice(0, 4)}-${alnum.slice(4, 8)}-${alnum.slice(8, 12)}`;
}
