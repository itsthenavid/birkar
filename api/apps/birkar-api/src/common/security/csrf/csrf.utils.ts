import { randomBytes, timingSafeEqual } from 'crypto';

export function generateCsrfToken(bytes = 32): string {
  return randomBytes(bytes).toString('hex');
}

export function safeEq(a: string, b: string): boolean {
  // timing-safe compare, but only if same length
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
