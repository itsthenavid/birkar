import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';

import { LockoutService } from './lockout.service';

/**
 * Safely read a header as string
 */
function readHeader(req: Request, name: string): string | undefined {
  const value = req.headers[name.toLowerCase()];
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.join(', ');
  return undefined;
}

/**
 * Resolve client IP in a proxy-safe way
 */
function resolveIp(req: Request): string {
  return (
    req.ip ??
    readHeader(req, 'x-forwarded-for')?.split(',')[0]?.trim() ??
    '0.0.0.0'
  );
}

@Injectable()
export class AuthRateLimitGuard implements CanActivate {
  constructor(private readonly lockout: LockoutService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<Request>();

    const ip = resolveIp(req);
    const path = req.path ?? 'unknown';

    // distributed + hardened lockout check (Redis-backed)
    const status = await this.lockout.check(`auth:${path}`, ip);

    if (status.blocked) {
      throw new HttpException(
        `Too many attempts. Retry after ${status.retryAfterSec}s`,
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }
}
