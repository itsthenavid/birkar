// src/modules/auth/auth.tokens.spec.ts
import 'dotenv/config';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import {
  buildCookieHeaderFromSetCookie,
  expectCookiePair,
  readSetCookieHeader,
  type HeadersLike,
} from '../../../test/utils/http-cookies';
import { getServer } from '../../../test/utils/supertest';
import { AppModule } from '../../app.module';

type BodyLike = Record<string, unknown>;

function asBodyLike(input: unknown): BodyLike {
  if (typeof input !== 'object' || input === null) return {};
  return input as BodyLike;
}

function asHeadersLike(input: unknown): HeadersLike {
  if (typeof input !== 'object' || input === null) return {};
  return input as HeadersLike;
}

function extractToken(bodyUnknown: unknown): string {
  const body = asBodyLike(bodyUnknown);
  const token = body['token'];
  if (typeof token !== 'string' || token.length === 0) {
    throw new Error(
      `Expected token string in body, got: ${JSON.stringify(body)}`,
    );
  }
  return token;
}

function extractUser(bodyUnknown: unknown): {
  email?: string;
  emailVerifiedAt?: unknown;
} {
  const body = asBodyLike(bodyUnknown);
  const userUnknown = body['user'];

  if (typeof userUnknown !== 'object' || userUnknown === null) {
    throw new Error(
      `Expected user object in body, got: ${JSON.stringify(body)}`,
    );
  }

  const user = userUnknown as Record<string, unknown>;
  return {
    email: typeof user['email'] === 'string' ? user['email'] : undefined,
    emailVerifiedAt: user['emailVerifiedAt'],
  };
}

describe('Auth v1 (tokens) (e2e-ish)', () => {
  let app: INestApplication;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';

    const mod = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = mod.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  it('verify email: request + confirm -> me shows emailVerifiedAt', async () => {
    const username = `u_${Date.now()}`;
    const email = `${username}@example.com`;
    const password = 'StrongPass_123!';

    const reg = await request(getServer(app))
      .post('/auth/register')
      .send({ username, email, password })
      .expect(201);

    const headers = asHeadersLike(reg.headers);
    const setCookie = readSetCookieHeader(headers);

    const sidName = process.env.SESSION_COOKIE_NAME ?? 'sid';
    expectCookiePair(setCookie, sidName);

    const cookieHeader = buildCookieHeaderFromSetCookie(setCookie);

    const reqTok = await request(getServer(app))
      .post('/auth/verify-email/request')
      .set('Cookie', cookieHeader)
      .send({})
      .expect(201);

    const token = extractToken(reqTok.body as unknown);

    await request(getServer(app))
      .post('/auth/verify-email/confirm')
      .send({ token })
      .expect(204);

    const me = await request(getServer(app))
      .get('/auth/me')
      .set('Cookie', cookieHeader)
      .expect(200);

    const user = extractUser(me.body as unknown);
    expect(user.email).toBe(email);
    expect(user.emailVerifiedAt).toBeTruthy();
  });

  it('password reset: request + confirm -> old password fails, new works, sessions invalidated', async () => {
    const username = `u_${Date.now()}_pw`;
    const email = `${username}@example.com`;
    const password = 'StrongPass_123!';
    const newPassword = 'NewStrongPass_456!';

    const reg = await request(getServer(app))
      .post('/auth/register')
      .send({ username, email, password })
      .expect(201);

    const headers = asHeadersLike(reg.headers);
    const cookieHeader = buildCookieHeaderFromSetCookie(
      readSetCookieHeader(headers),
    );

    await request(getServer(app))
      .get('/auth/me')
      .set('Cookie', cookieHeader)
      .expect(200);

    const reqReset = await request(getServer(app))
      .post('/auth/password/reset/request')
      .send({ identifier: email })
      .expect(201);

    const token = extractToken(reqReset.body as unknown);

    await request(getServer(app))
      .post('/auth/password/reset/confirm')
      .send({ token, newPassword })
      .expect(204);

    await request(getServer(app))
      .get('/auth/me')
      .set('Cookie', cookieHeader)
      .expect(401);

    await request(getServer(app))
      .post('/auth/login')
      .send({ identifier: email, password })
      .expect(401);

    const login2 = await request(getServer(app))
      .post('/auth/login')
      .send({ identifier: email, password: newPassword })
      .expect(201);

    const headers2 = asHeadersLike(login2.headers);
    const cookie2 = buildCookieHeaderFromSetCookie(
      readSetCookieHeader(headers2),
    );

    await request(getServer(app))
      .get('/auth/me')
      .set('Cookie', cookie2)
      .expect(200);
  });
});
