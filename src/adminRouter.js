import express from 'express';
import bcrypt from 'bcrypt';
import { Prisma } from '@prisma/client';
import { signAdminToken, requireAdminJwt } from './adminAuth.js';

function prismaFail(res, e, logTag) {
  console.error(logTag, e);
  if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2022') {
    return res.status(503).json({
      ok: false,
      error: 'database_schema_outdated',
      message:
        'Database is missing a column (e.g. Admin.username). Run: npx prisma migrate deploy — then restart the license server.'
    });
  }
  return res.status(500).json({
    ok: false,
    error: 'server_error',
    message: process.env.NODE_ENV !== 'production' ? e.message : undefined
  });
}

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
      return res.json({
        ok: true,
        token,
        email: admin.email,
        username: admin.username
      });
    } catch (e) {
      return prismaFail(res, e, '[admin/login]');
    }
  });

  router.get('/me', requireAdminJwt, async (req, res) => {
    try {
      const admin = await prisma.admin.findUnique({
        where: { id: req.admin.id },
        select: { id: true, email: true, username: true }
      });
      if (!admin) {
        return res.status(404).json({ ok: false, error: 'not_found' });
      }
      return res.json({ ok: true, admin });
    } catch (e) {
      return prismaFail(res, e, '[admin/me get]');
    }
  });

  router.patch('/me', requireAdminJwt, async (req, res) => {
    try {
      const id = req.admin.id;
      const body = req.body || {};
      const usernameRaw =
        body.username !== undefined ? String(body.username).trim() : null;
      const newPassword = body.newPassword !== undefined ? String(body.newPassword) : '';
      const currentPassword = body.currentPassword !== undefined ? String(body.currentPassword) : '';

      const admin = await prisma.admin.findUnique({ where: { id } });
      if (!admin) {
        return res.status(404).json({ ok: false, error: 'not_found' });
      }

      const updates = {};
      if (usernameRaw !== null && usernameRaw !== admin.username) {
        if (!usernameRaw || usernameRaw.length > 80) {
          return res.status(400).json({
            ok: false,
            error: 'invalid_username',
            message: 'Username is required (max 80 characters).'
          });
        }
        updates.username = usernameRaw;
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
        return res.json({
          ok: true,
          admin: { id: admin.id, email: admin.email, username: admin.username }
        });
      }

      const updated = await prisma.admin.update({ where: { id }, data: updates });
      const token = signAdminToken(updated);
      return res.json({
        ok: true,
        admin: { id: updated.id, email: updated.email, username: updated.username },
        token
      });
    } catch (e) {
      return prismaFail(res, e, '[admin/me patch]');
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
          fullName: row.fullName,
          phone: row.phone,
          address: row.address,
          birthday: row.birthday ? row.birthday.toISOString().slice(0, 10) : null,
          createdAt: row.createdAt.toISOString()
        }))
      });
    } catch (e) {
      return prismaFail(res, e, '[admin/licenses]');
    }
  });

  return router;
}
