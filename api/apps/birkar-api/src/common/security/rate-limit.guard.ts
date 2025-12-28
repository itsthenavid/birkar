import {
  BadRequestException,
  CanActivate,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';
import { ENV } from '../constants/env.constants';

type BucketKey = string;

function numEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  const n = raw ? Number(raw) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

@Injectable()
export class AuthRateLimitGuard implements CanActivate {
  private memory = new Map<BucketKey, { count: number; resetAt: number }>();

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();

    const windowSec = numEnv(ENV.AUTH_RL_WINDOW_SEC, 60);
    const max = numEnv(ENV.AUTH_RL_MAX, 15);

    const ip =
      (req.headers['x-forwarded-for'] as string | undefined)
        ?.split(',')[0]
        ?.trim() ??
      req.socket.remoteAddress ??
      'unknown';

    const key = `${req.method}:${req.path}:${ip}`;

    const now = Date.now();
    const windowMs = windowSec * 1000;

    const entry = this.memory.get(key);
    if (!entry || entry.resetAt <= now) {
      this.memory.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }

    entry.count += 1;
    if (entry.count > max) throw new BadRequestException('Rate limit exceeded');

    return true;
  }
}
