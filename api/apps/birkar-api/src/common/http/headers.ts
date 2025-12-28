// src/common/http/headers.ts
import type { Request } from 'express';

/**
 * Read a header as a single string (safe + typed).
 * - string        -> same
 * - string[]      -> joined with space
 * - undefined     -> undefined
 * - anything else -> undefined (fail-safe)
 */
export function readHeaderString(
  req: Request,
  name: string,
): string | undefined {
  const v: unknown =
    req.headers[name.toLowerCase() as keyof typeof req.headers];

  if (typeof v === 'string') return v.trim() || undefined;
  if (Array.isArray(v) && v.every((x) => typeof x === 'string')) {
    const s = v
      .map((x) => x.trim())
      .filter(Boolean)
      .join(' ');
    return s || undefined;
  }

  return undefined;
}

/**
 * Resolve request IP in a stable way.
 * Prefer Express' req.ip when behind proxy is configured,
 * otherwise fallback to socket address.
 */
export function resolveIp(req: Request): string | undefined {
  return req.ip || req.socket.remoteAddress || undefined;
}
