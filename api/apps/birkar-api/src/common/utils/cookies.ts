// src/common/utils/cookies.ts
import type { CookieOptions } from 'express';
import { ENV } from '../constants/env.constants';

function envBool(v: string | undefined, fallback = false): boolean {
  if (typeof v !== 'string') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
}

function envInt(v: string | undefined, fallback: number): number {
  if (typeof v !== 'string') return fallback;
  const n = Number(v);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function isProd(): boolean {
  return (process.env.NODE_ENV ?? '').toLowerCase() === 'production';
}

function normalizeSameSite(input: string): CookieOptions['sameSite'] {
  const v = input.trim().toLowerCase();
  if (v === 'none') return 'none';
  if (v === 'strict') return 'strict';
  return 'lax';
}

/**
 * Session cookie options:
 * - httpOnly=true (prevents JS access)
 * - sameSite=lax (good default for modern apps)
 * - secure=true in prod (recommended)
 * - maxAge configurable (default 30 days)
 */
export function buildSessionCookieOptions(): CookieOptions {
  const domain = (process.env[ENV.COOKIE_DOMAIN] ?? '').trim() || undefined;
  const path = (process.env[ENV.COOKIE_PATH] ?? '/').trim() || '/';

  const sameSite = normalizeSameSite(process.env[ENV.COOKIE_SAMESITE] ?? 'lax');

  // If you deploy behind TLS termination proxy, set COOKIE_SECURE=1 in prod.
  // In dev you might keep it off for localhost http.
  const secure = envBool(process.env[ENV.COOKIE_SECURE], isProd());

  const maxAgeDays = envInt(process.env.SESSION_COOKIE_MAX_AGE_DAYS, 30);
  const maxAge = 1000 * 60 * 60 * 24 * Math.max(1, maxAgeDays);

  return {
    httpOnly: true,
    secure,
    sameSite,
    domain,
    path,
    maxAge,
  };
}

/**
 * CSRF cookie options:
 * - identical to session cookie but httpOnly=false (double-submit)
 */
export function buildCsrfCookieOptions(): CookieOptions {
  const base = buildSessionCookieOptions();
  return { ...base, httpOnly: false };
}

export const DEV_IMPERSONATE_HEADER = 'x-dev-user-id' as const;
