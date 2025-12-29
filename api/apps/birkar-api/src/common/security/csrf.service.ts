// src/common/security/csrf.service.ts
import { Injectable } from '@nestjs/common';
import { randomBytes, timingSafeEqual } from 'node:crypto';

@Injectable()
export class CsrfService {
  generateToken(): string {
    // 32 bytes -> 43 char base64url-ish after replace, good enough
    return randomBytes(32)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  verify(expected: string, actual: string): boolean {
    if (!expected || !actual) return false;
    if (expected.length !== actual.length) return false;

    // constant-time compare
    const a = Buffer.from(expected);
    const b = Buffer.from(actual);
    return timingSafeEqual(a, b);
  }
}
