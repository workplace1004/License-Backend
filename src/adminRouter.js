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
      return res.json({ ok: true, token, email: admin.email });
    } catch (e) {
      console.error('[admin/login]', e);
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  router.get('/me', requireAdminJwt, async (req, res) => {
    try {
      const admin = await prisma.admin.findUnique({
        where: { id: req.admin.id },
        select: { id: true, email: true }
      });
      if (!admin) {
        return res.status(404).json({ ok: false, error: 'not_found' });
      }
      return res.json({ ok: true, admin });
    } catch (e) {
      console.error('[admin/me get]', e);
      return res.status(500).json({ ok: false, error: 'server_error' });
    }
  });

  router.patch('/me', requireAdminJwt, async (req, res) => {
    try {
      const id = req.admin.id;
      const body = req.body || {};
      const emailRaw = body.email !== undefined ? String(body.email).trim().toLowerCase() : null;
      const newPassword = body.newPassword !== undefined ? String(body.newPassword) : '';
      const currentPassword = body.currentPassword !== undefined ? String(body.currentPassword) : '';

      const admin = await prisma.admin.findUnique({ where: { id } });
      if (!admin) {
        return res.status(404).json({ ok: false, error: 'not_found' });
      }

      const updates = {};
      if (emailRaw !== null && emailRaw !== admin.email) {
        if (!emailRaw || !emailRaw.includes('@')) {
          return res.status(400).json({ ok: false, error: 'invalid_email', message: 'Valid email is required.' });
        }
        const taken = await prisma.admin.findUnique({ where: { email: emailRaw } });
        if (taken) {
          return res.status(409).json({ ok: false, error: 'email_taken', message: 'That email is already in use.' });
        }
        updates.email = emailRaw;
      }

      if (newPassword) {
        if (newPassword.length < 6) {
          return res.status(400).json({
            ok: false,
            error: 'weak_password',
            message: 'New password must be at least 6 characters.'
          });
        }
        if (!currentPassword) {
          return res.status(400).json({
            ok: false,
            error: 'current_password_required',
            message: 'Enter your current password to set a new one.'
          });
        }
        const match = await bcrypt.compare(currentPassword, admin.passwordHash);
        if (!match) {
          return res.status(401).json({
            ok: false,
            error: 'invalid_current_password',
            message: 'Current password is incorrect.'
          });
        }
        updates.passwordHash = await bcrypt.hash(newPassword, 10);
      }

      if (Object.keys(updates).length === 0) {
        return res.json({ ok: true, admin: { id: admin.id, email: admin.email } });
      }

      const updated = await prisma.admin.update({ where: { id }, data: updates });
      const token = signAdminToken(updated);
      return res.json({
        ok: true,
        admin: { id: updated.id, email: updated.email },
        token
      });
    } catch (e) {
      console.error('[admin/me patch]', e);
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
