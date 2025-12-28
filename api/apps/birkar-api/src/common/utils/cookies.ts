import type { CookieOptions } from 'express';
import { ENV } from '../constants/env.constants';

function envBool(v: string | undefined, fallback = false): boolean {
  if (typeof v !== 'string') return fallback;
  return ['1', 'true', 'yes', 'on'].includes(v.trim().toLowerCase());
}

export function buildSessionCookieOptions(): CookieOptions {
  const secure = envBool(process.env[ENV.COOKIE_SECURE], false);
  const domain = (process.env[ENV.COOKIE_DOMAIN] ?? '').trim() || undefined;
  const path = (process.env[ENV.COOKIE_PATH] ?? '/').trim() || '/';
  const sameSiteRaw = (process.env[ENV.COOKIE_SAMESITE] ?? 'lax')
    .trim()
    .toLowerCase();

  const sameSite =
    sameSiteRaw === 'none'
      ? 'none'
      : sameSiteRaw === 'strict'
        ? 'strict'
        : 'lax';

  return {
    httpOnly: true,
    secure,
    sameSite,
    domain,
    path,
  };
}

export function buildCsrfCookieOptions(): CookieOptions {
  const base = buildSessionCookieOptions();
  return {
    ...base,
    httpOnly: false, // double-submit
  };
}
