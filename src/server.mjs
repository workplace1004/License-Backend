/** License API only: do not import the POS `backend` app or share its database. */
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import { createLicenseRouter } from './router.js';

const prisma = new PrismaClient();
const app = express();
const PORT = Number(process.env.PORT || 5050);

app.use(cors({ origin: true }));
app.use(express.json({ limit: '128kb' }));

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'pos-license-server' });
});

app.use('/license', createLicenseRouter(prisma));

app.listen(PORT, () => {
  console.log(`POS license API http://0.0.0.0:${PORT}  (POST /license/create|activate|validate)`);
});
