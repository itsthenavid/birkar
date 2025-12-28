import crypto from 'crypto';

const TOKEN_BYTES = 32; // 256-bit

/**
 * Optional pepper: keep it stable across environments.
 * Put in .env as AUTH_TOKEN_PEPPER="..."
 */
function pepper(): string {
  return process.env.AUTH_TOKEN_PEPPER ?? '';
}

/**
 * Raw token to send via email (or return in tests).
 * URL-safe base64.
 */
export function generateRawToken(): string {
  const raw = crypto.randomBytes(TOKEN_BYTES);
  return raw
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

/**
 * Hash token before storing in DB.
 * Never store raw tokens.
 */
export function hashToken(rawToken: string): string {
  return crypto
    .createHash('sha256')
    .update(`${rawToken}.${pepper()}`)
    .digest('hex');
}

/**
 * Constant-time compare for hashes.
 */
export function safeEqualHex(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return crypto.timingSafeEqual(aBuf, bBuf);
}
