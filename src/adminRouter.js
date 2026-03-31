import express from 'express';
import bcrypt from 'bcrypt';
import { signAdminToken, requireAdminJwt } from './adminAuth.js';

/**
 * @param {import('@prisma/client').PrismaClient} prisma
 */
export function createAdminRouter(prisma) {
  const router = express.Router();

  router.post('/login', async (req, res) => {
    try {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const password = String(req.body?.password || '');
      if (!email || !password) {
        return res.status(400).json({ ok: false, error: 'bad_request', message: 'Email and password are required.' });
      }
      const admin = await prisma.admin.findUnique({ where: { email } });
      if (!admin) {
        return res.status(401).json({ ok: false, error: 'invalid_credentials', message: 'Invalid email or password.' });
      }
      const match = await bcrypt.compare(password, admin.passwordHash);
      if (!match) {
        return res.status(401).json({ ok: false, error: 'invalid_credentials', message: 'Invalid email or password.' });
      }
      let token;
      try {
        token = signAdminToken(admin);
      } catch (e) {
        console.error('[admin/login]', e);
        return res.status(500).json({
          ok: false,
          error: 'auth_misconfigured',
          message: e.message || 'Server auth is not configured.'
        });
      }
      return res.json({ ok: true, token });
    } catch (e) {
      console.error('[admin/login]', e);
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  router.get('/licenses', requireAdminJwt, async (req, res) => {
    try {
      const rows = await prisma.license.findMany({ orderBy: { createdAt: 'desc' } });
      return res.json({
        ok: true,
        licenses: rows.map((row) => ({
          id: row.id,
          licenseKey: row.licenseKey,
          email: row.email,
          deviceFingerprint: row.deviceFingerprint,
          isActivated: row.isActivated,
          expiresAt: row.expiresAt.toISOString(),
          createdAt: row.createdAt.toISOString()
        }))
      });
    } catch (e) {
      console.error('[admin/licenses]', e);
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  return router;
}
