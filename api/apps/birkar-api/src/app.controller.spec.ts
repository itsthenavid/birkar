import 'dotenv/config';

process.env.NODE_ENV = 'development';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { Server } from 'http';
import request from 'supertest';

import { AppModule } from './app.module';
import { PrismaService } from './modules/prisma/prisma.service';

describe('AppController (e2e-ish)', () => {
  let app: INestApplication;
  let server: Server;
  let prisma: PrismaService;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();

    server = app.getHttpServer() as Server;
    prisma = app.get(PrismaService);
  });

  afterAll(async () => {
    await app.close();
  });

  it('GET /health -> ok', async () => {
    await request(server).get('/health').expect(200).expect({ ok: true });
  });

  it('GET /admin/ping without header -> 401 (dev impersonation)', async () => {
    await request(server).get('/admin/ping').expect(401);
  });

  it('GET /admin/ping with x-dev-user-id -> 200 OR 403 (depends on perms)', async () => {
    const email = process.env.SEED_SUPERUSER_EMAIL?.trim().toLowerCase();
    const username = process.env.SEED_SUPERUSER_USERNAME?.trim().toLowerCase();

    const user =
      (email
        ? await prisma.user.findUnique({
            where: { email },
            select: { id: true },
          })
        : null) ??
      (username
        ? await prisma.user.findUnique({
            where: { username },
            select: { id: true },
          })
        : null);

    if (!user) {
      throw new Error(
        'No seeded user found. Run: pnpm prisma db seed (with SEED_SUPERUSER_*)',
      );
    }

    const res = await request(server)
      .get('/admin/ping')
      .set('x-dev-user-id', user.id);

    expect([200, 403]).toContain(res.status);
  });
});
