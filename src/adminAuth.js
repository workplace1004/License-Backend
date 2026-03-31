import jwt from 'jsonwebtoken';

const DEV_JWT_FALLBACK = 'dev-only-pos-license-admin-jwt';

/**
 * Used to sign/verify admin session tokens. Falls back to LICENSE_ADMIN_SECRET so one value can serve both.
 * In non-production, if neither is set, uses a fixed dev fallback (set LICENSE_ADMIN_JWT_SECRET in production).
 */
export function getAdminJwtSecret() {
  const a = process.env.LICENSE_ADMIN_JWT_SECRET;
  if (a && String(a).trim()) return String(a).trim();
  const b = process.env.LICENSE_ADMIN_SECRET;
  if (b && String(b).trim()) return String(b).trim();
  if (process.env.NODE_ENV !== 'production') return DEV_JWT_FALLBACK;
  return '';
}

/**
 * @param {{ id: string, email: string }} admin
 */
export function signAdminToken(admin) {
  const secret = getAdminJwtSecret();
  if (!secret) {
    throw new Error('Set LICENSE_ADMIN_JWT_SECRET or LICENSE_ADMIN_SECRET for admin login.');
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
