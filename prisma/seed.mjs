import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

const ADMIN_EMAIL = 'admin@gmail.com';
const ADMIN_PASSWORD = '123123';

async function main() {
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 10);
  await prisma.admin.upsert({
    where: { email: ADMIN_EMAIL },
    update: { passwordHash },
    create: {
      email: ADMIN_EMAIL,
      passwordHash
    }
  });
  console.log('Seeded admin:', ADMIN_EMAIL);
}

main()
  .then(() => prisma.$disconnect())
  .catch((e) => {
    console.error(e);
    prisma.$disconnect();
    process.exit(1);
  });
