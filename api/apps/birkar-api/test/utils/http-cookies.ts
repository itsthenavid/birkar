// src/common/http/http-cookies.ts
import type { Request } from 'express';

export type HeadersLike = Record<string, string | string[] | undefined>;

/**
 * Read "set-cookie" header safely as string[] (supertest can give string | string[] | undefined)
 */
export function readSetCookieHeader(headers: HeadersLike): string[] {
  const v = headers['set-cookie'];
  if (Array.isArray(v))
    return v.filter((x): x is string => typeof x === 'string');
  if (typeof v === 'string') return [v];
  return [];
}

/**
 * Get "name=value" from a single Set-Cookie line.
 */
export function cookiePairFromSetCookieLine(line: string): string | null {
  const first = line.split(';')[0]?.trim();
  if (!first) return null;
  const eq = first.indexOf('=');
  if (eq <= 0) return null;
  return first;
}

/**
 * Build a Cookie header value from set-cookie lines:
 * "a=1; b=2"
 */
export function buildCookieHeaderFromSetCookie(
  setCookieLines: string[],
): string {
  return setCookieLines
    .map(cookiePairFromSetCookieLine)
    .filter((x): x is string => typeof x === 'string' && x.length > 0)
    .join('; ');
}

/**
 * Find "name=value" in set-cookie lines.
 */
export function pickCookiePair(
  setCookieLines: string[],
  name: string,
): string | null {
  const prefix = `${name}=`;
  for (const line of setCookieLines) {
    const pair = cookiePairFromSetCookieLine(line);
    if (pair && pair.startsWith(prefix)) return pair;
  }
  return null;
}

/**
 * Assert cookie exists, otherwise throw with a helpful message.
 */
export function expectCookiePair(
  setCookieLines: string[],
  name: string,
): string {
  const c = pickCookiePair(setCookieLines, name);
  if (!c) {
    throw new Error(
      `Expected cookie "${name}" in set-cookie. Got:\n` +
        setCookieLines.map((x) => `- ${x}`).join('\n'),
    );
  }
  return c;
}

/**
 * Optional helper for tests/controllers: read Cookie header safely as a single string.
 */
export function readCookieHeader(req: Request): string | undefined {
  const v: unknown = req.headers.cookie;
  if (typeof v === 'string') return v.trim() || undefined;
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
    const s = v
      .map((x) => x.trim())
      .filter(Boolean)
      .join('; ');
    return s || undefined;
  }
  return undefined;
}
