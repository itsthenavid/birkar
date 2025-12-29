// test/e2e/auth.token-rate-limit.e2e-spec.ts
import 'dotenv/config';

import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'crypto';
import request from 'supertest';

import { AppModule } from '../../src/app.module';
import { RedisService } from '../../src/modules/redis/redis.service';
import {
  buildCookieHeaderFromSetCookie,
  readSetCookieHeader,
} from '../utils/http-cookies';
import { getServer } from '../utils/supertest';

type HeadersLike = Record<string, string | string[] | undefined>;

function asHeadersLike(input: unknown): HeadersLike {
  if (typeof input !== 'object' || input === null) return {};
  return input as HeadersLike;
}

type JsonObject = Record<string, unknown>;
type JsonBody = JsonObject | string;

type HitOptions = {
  cookie?: string;
  body?: JsonBody | null;
  headers?: Record<string, string>;
};

function hit(
  app: INestApplication,
  method: 'get' | 'post',
  url: string,
  opts?: HitOptions,
): request.Test {
  const r = request(getServer(app))[method](url);

  if (opts?.cookie) r.set('Cookie', opts.cookie);
  if (opts?.headers) {
    for (const [k, v] of Object.entries(opts.headers)) r.set(k, v);
  }

  // supertest.send cannot accept null
  if (opts?.body !== undefined && opts.body !== null) r.send(opts.body);

  return r;
}

function shortId(len: number): string {
  return randomUUID().replace(/-/g, '').slice(0, len);
}

function makeUsername(prefix = 'u'): string {
  return `${prefix}_${shortId(18)}`; // <= 32 chars
}

function safeJson(res: request.Response): JsonObject {
  const b: unknown = res.body;
  return typeof b === 'object' && b !== null ? (b as JsonObject) : {};
}

function headerToString(v: string | string[] | undefined): string | undefined {
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v[0];
  return undefined;
}

function parseRetryAfterSec(res: request.Response): number | undefined {
  // Prefer standard header if present
  const h = headerToString(
    (res.headers as unknown as HeadersLike)['retry-after'],
  );
  if (h) {
    const n = Number(h);
    if (Number.isFinite(n) && n > 0) return n;
  }

  // Fallback to JSON body
  const json = safeJson(res);
  const ra = json['retryAfterSec'];
  if (typeof ra === 'number' && Number.isFinite(ra) && ra > 0) return ra;

  return undefined;
}

describe('Auth (TokenRateLimitGuard) (e2e)', () => {
  let app: INestApplication;
  let redis: RedisService;

  beforeAll(async () => {
    process.env.NODE_ENV = 'test';

    // ---- Fast + deterministic RL settings for CI ----
    process.env.TOKEN_PASSWORD_RESET_WINDOW_SEC = '30';
    process.env.TOKEN_PASSWORD_RESET_MAX = '2';
    process.env.TOKEN_PASSWORD_RESET_BLOCK_SEC = '60';

    process.env.TOKEN_VERIFY_EMAIL_WINDOW_SEC = '30';
    process.env.TOKEN_VERIFY_EMAIL_MAX = '2';
    process.env.TOKEN_VERIFY_EMAIL_BLOCK_SEC = '60';

    // optional confirms (recommended)
    process.env.TOKEN_PASSWORD_RESET_CONFIRM_WINDOW_SEC = '30';
    process.env.TOKEN_PASSWORD_RESET_CONFIRM_MAX = '3';
    process.env.TOKEN_PASSWORD_RESET_CONFIRM_BLOCK_SEC = '60';

    process.env.TOKEN_VERIFY_EMAIL_CONFIRM_WINDOW_SEC = '30';
    process.env.TOKEN_VERIFY_EMAIL_CONFIRM_MAX = '3';
    process.env.TOKEN_VERIFY_EMAIL_CONFIRM_BLOCK_SEC = '60';

    // stable cookie name for tests
    process.env.SESSION_COOKIE_NAME = process.env.SESSION_COOKIE_NAME ?? 'sid';

    const mod = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = mod.createNestApplication();
    await app.init();

    redis = app.get(RedisService);
  });

  beforeEach(async () => {
    await redis.redis.flushdb();
  });

  afterAll(async () => {
    await app.close();
  });

  it('password reset request: blocks after max attempts (public endpoint)', async () => {
    const email = `rl_pw_${Date.now()}_${shortId(6)}@example.com`;

    await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: email },
    }).expect(201);

    await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: email },
    }).expect(201);

    const third = await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: email },
    }).expect(429);

    // ✅ your API returns JSON for 429; assert on body + standard Retry-After
    const json = safeJson(third);
    expect(json['ok']).toBe(false);
    expect(json['error']).toBe('RATE_LIMITED');

    const retryAfter = parseRetryAfterSec(third);
    expect(retryAfter).toBeDefined();
    expect(retryAfter).toBeGreaterThan(0);
  });

  it('password reset request: different identifiers do not share the same bucket (identifierHash keying)', async () => {
    const a = `rl_pw_a_${Date.now()}_${shortId(4)}@example.com`;
    const b = `rl_pw_b_${Date.now()}_${shortId(4)}@example.com`;

    await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: a },
    }).expect(201);

    await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: a },
    }).expect(201);

    await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: a },
    }).expect(429);

    // B should still be allowed
    await hit(app, 'post', '/auth/password/reset/request', {
      body: { identifier: b },
    }).expect(201);
  });

  it('verify email request: blocks after max attempts (session + userId keying)', async () => {
    const username = makeUsername('rlu');
    const email = `${username}@example.com`;
    const password = 'StrongPass_123!';

    const reg = await hit(app, 'post', '/auth/register', {
      body: { username, email, password },
    }).expect(201);

    const setCookie = readSetCookieHeader(asHeadersLike(reg.headers));
    const cookieHeader = buildCookieHeaderFromSetCookie(setCookie);

    await hit(app, 'post', '/auth/verify-email/request', {
      cookie: cookieHeader,
      body: {},
    }).expect(201);

    await hit(app, 'post', '/auth/verify-email/request', {
      cookie: cookieHeader,
      body: {},
    }).expect(201);

    await hit(app, 'post', '/auth/verify-email/request', {
      cookie: cookieHeader,
      body: {},
    }).expect(429);
  });

  it('verify email request: requires session (SessionGuard)', async () => {
    await hit(app, 'post', '/auth/verify-email/request', {
      body: {},
    }).expect(401);
  });
});
