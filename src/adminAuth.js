import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const DEV_JWT_FALLBACK = 'dev-only-pos-license-admin-jwt';

/** Stable HMAC key derived from DATABASE_URL when no explicit JWT secret is set (production convenience on Railway). */
function derivedJwtSecretFromDatabaseUrl() {
  const db = process.env.DATABASE_URL;
  if (!db || !String(db).trim()) return '';
  return crypto
    .createHash('sha256')
    .update(`pos-license-admin-jwt-v1|${String(db).trim()}`, 'utf8')
    .digest('hex');
}

/**
 * Used to sign/verify admin session tokens. Falls back to LICENSE_ADMIN_SECRET so one value can serve both.
 * Dev: fixed fallback. Production: if unset, derives from DATABASE_URL (set LICENSE_ADMIN_JWT_SECRET to override).
 */
export function getAdminJwtSecret() {
  const a = process.env.LICENSE_ADMIN_JWT_SECRET;
  if (a && String(a).trim()) return String(a).trim();
  const b = process.env.LICENSE_ADMIN_SECRET;
  if (b && String(b).trim()) return String(b).trim();
  if (process.env.NODE_ENV !== 'production') return DEV_JWT_FALLBACK;
  return derivedJwtSecretFromDatabaseUrl() || '';
}

/**
 * @param {{ id: string, email: string }} admin
 */
export function signAdminToken(admin) {
  const secret = getAdminJwtSecret();
  if (!secret) {
    throw new Error(
      'Set LICENSE_ADMIN_JWT_SECRET, LICENSE_ADMIN_SECRET, or DATABASE_URL so admin JWT signing can run.'
    );
  }
  return jwt.sign({ sub: admin.id, email: admin.email, typ: 'admin' }, secret, { expiresIn: '7d' });
}

/**
 * Bearer JWT (admin) or raw LICENSE_ADMIN_SECRET as Bearer (legacy API clients).
 */
export function authorizeLicenseAdminRequest(req) {
  const h = req.headers.authorization || '';
  const bearer = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  if (!bearer) return false;
  const legacy = process.env.LICENSE_ADMIN_SECRET;
  if (legacy && String(legacy).trim() && bearer === String(legacy).trim()) return true;
  const secret = getAdminJwtSecret();
  if (!secret) return false;
  try {
    const p = jwt.verify(bearer, secret);
    return p?.typ === 'admin' && typeof p?.sub === 'string';
  } catch {
    return false;
  }
}

export function requireAdminJwt(req, res, next) {
  const h = req.headers.authorization || '';
  const bearer = h.startsWith('Bearer ') ? h.slice(7).trim() : '';
  const secret = getAdminJwtSecret();
  if (!bearer || !secret) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  try {
    const p = jwt.verify(bearer, secret);
    if (p?.typ !== 'admin' || typeof p?.sub !== 'string') {
      return res.status(401).json({ ok: false, error: 'unauthorized' });
    }
    req.admin = { id: p.sub, email: p.email };
    return next();
  } catch {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
}
