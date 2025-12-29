import type { Request } from 'express';

export function readHeaderString(
  req: Request,
  name: string,
): string | undefined {
  const v = req.headers[name.toLowerCase()];
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return v[0];
  return undefined;
}

/**
 * Proxy-safe IP resolver:
 * - If trust proxy is enabled in Nest/Express, req.ip is already derived safely.
 * - Avoid trusting x-forwarded-for manually unless you really know what you're doing.
 */
export function resolveIp(req: Request): string | undefined {
  // Express gives a normalized IP when trust proxy is set properly.
  const ip = req.ip;
  if (typeof ip === 'string' && ip.length > 0) return ip;

  // fallback (rare)
  const ra = req.socket?.remoteAddress;
  return typeof ra === 'string' && ra.length > 0 ? ra : undefined;
}
