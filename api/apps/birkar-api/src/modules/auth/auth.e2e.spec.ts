import 'dotenv/config';
process.env.NODE_ENV = 'development';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { Server } from 'http';
import request from 'supertest';

import { AppModule } from '../../app.module';

function asCookieArray(v: unknown): string[] {
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) return v;
  if (typeof v === 'string') return [v];
  return [];
}

function extractCookie(setCookieHeader: unknown, name: string): string | null {
  const rows = asCookieArray(setCookieHeader);
  const row = rows.find((c) => c.startsWith(`${name}=`));
  if (!row) return null;
  return row.split(';')[0]; // "name=value"
}

type OkBody = { ok: boolean; user?: { id: string } };

describe('Auth v1 (e2e-ish)', () => {
  let app: INestApplication;
  let server: Server;

  beforeAll(async () => {
    const mod = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = mod.createNestApplication();
    await app.init();

    server = app.getHttpServer() as Server;
  });

  afterAll(async () => {
    await app.close();
  });

  it('register -> sets session cookie', async () => {
    const username = `u_${Date.now()}`;
    const email = `${username}@test.local`;

    const res = await request(server)
      .post('/auth/register')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy'])
      .send({ username, email, password: 'StrongPass_123!' })
      .expect(201);

    const body = res.body as OkBody;
    expect(body.ok).toBe(true);

    const sid = extractCookie(
      res.headers['set-cookie'],
      process.env.SESSION_COOKIE_NAME ?? 'sid',
    );
    expect(sid).toBeTruthy();
  });

  it('login -> sets session cookie, me works', async () => {
    const identifier =
      process.env.SEED_SUPERUSER_EMAIL ?? 'founder@birkar.local';
    const password =
      process.env.SEED_SUPERUSER_PASSWORD ?? 'ChangeMe_DevOnly_123!';

    const loginRes = await request(server)
      .post('/auth/login')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy'])
      .send({ identifier, password })
      .expect(201);

    const sidCookie = extractCookie(
      loginRes.headers['set-cookie'],
      process.env.SESSION_COOKIE_NAME ?? 'sid',
    );
    expect(sidCookie).toBeTruthy();

    const meRes = await request(server)
      .get('/auth/me')
      .set('Cookie', [sidCookie!])
      .expect(200);

    const meBody = meRes.body as OkBody;
    expect(meBody.ok).toBe(true);
    expect(meBody.user?.id).toBeTruthy();
  });

  it('logout -> invalidates session', async () => {
    const identifier =
      process.env.SEED_SUPERUSER_EMAIL ?? 'founder@birkar.local';
    const password =
      process.env.SEED_SUPERUSER_PASSWORD ?? 'ChangeMe_DevOnly_123!';

    const loginRes = await request(server)
      .post('/auth/login')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy'])
      .send({ identifier, password })
      .expect(201);

    const sidCookie = extractCookie(
      loginRes.headers['set-cookie'],
      process.env.SESSION_COOKIE_NAME ?? 'sid',
    );
    expect(sidCookie).toBeTruthy();

    await request(server)
      .post('/auth/logout')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy', sidCookie!])
      .expect(201);

    await request(server)
      .get('/auth/me')
      .set('Cookie', [sidCookie!])
      .expect(401);
  });
});
