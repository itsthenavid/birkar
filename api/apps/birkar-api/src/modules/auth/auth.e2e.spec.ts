// src/modules/auth/auth.e2e.spec.ts
import 'dotenv/config';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'crypto';
import request from 'supertest';

import {
  expectCookiePair,
  readSetCookieHeader,
  type HeadersLike,
} from '../../../test/utils/http-cookies';
import { getServer } from '../../../test/utils/supertest';
import { AppModule } from '../../app.module';

type OkBody = { ok: boolean; user?: { id: string } };

function asHeadersLike(input: unknown): HeadersLike {
  if (typeof input !== 'object' || input === null) return {};
  return input as HeadersLike;
}

function shortId(len: number): string {
  return randomUUID().replace(/-/g, '').slice(0, len);
}

function makeUsername(prefix = 'u'): string {
  return `${prefix}_${shortId(18)}`; // <= 32 always
}

describe('Auth v1 (e2e-ish)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    // IMPORTANT: tests must run in test env
    process.env.NODE_ENV = 'test';
    process.env.SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME ?? 'sid';

    const mod = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = mod.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('register -> sets session cookie', async () => {
    const username = makeUsername('u');
    const email = `${username}@test.local`;

    const res = await request(getServer(app))
      .post('/auth/register')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy'])
      .send({ username, email, password: 'StrongPass_123!' })
      .expect(201);

    const body = res.body as OkBody;
    expect(body.ok).toBe(true);

    const setCookie = readSetCookieHeader(asHeadersLike(res.headers));
    expectCookiePair(setCookie, process.env.SESSION_COOKIE_NAME ?? 'sid');
  });

  it('login -> sets session cookie, me works', async () => {
    const identifier =
      process.env.SEED_SUPERUSER_EMAIL ?? 'founder@birkar.local';
    const password =
      process.env.SEED_SUPERUSER_PASSWORD ?? 'ChangeMe_DevOnly_123!';

    const loginRes = await request(getServer(app))
      .post('/auth/login')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy'])
      .send({ identifier, password })
      .expect(201);

    const setCookie = readSetCookieHeader(asHeadersLike(loginRes.headers));
    const sidCookie = expectCookiePair(
      setCookie,
      process.env.SESSION_COOKIE_NAME ?? 'sid',
    );

    const meRes = await request(getServer(app))
      .get('/auth/me')
      .set('Cookie', [sidCookie])
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

    const loginRes = await request(getServer(app))
      .post('/auth/login')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy'])
      .send({ identifier, password })
      .expect(201);

    const setCookie = readSetCookieHeader(asHeadersLike(loginRes.headers));
    const sidCookie = expectCookiePair(
      setCookie,
      process.env.SESSION_COOKIE_NAME ?? 'sid',
    );

    await request(getServer(app))
      .post('/auth/logout')
      .set('x-csrf-token', 'dummy')
      .set('Cookie', ['csrf=dummy', sidCookie])
      .expect(201);

    await request(getServer(app))
      .get('/auth/me')
      .set('Cookie', [sidCookie])
      .expect(401);
  });
});
