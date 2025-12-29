// src/common/security/token-rate-limit.guard.ts
import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import type { AuditAction } from '@prisma/client';
import { RedisService } from '../../modules/redis/redis.service';
import { AuditService } from '../audit/audit.service';
import { readHeaderString, resolveIp } from '../http/headers';
import { sha256Hex } from '../utils/crypto';
import { normalizeEmail } from '../utils/normalize';

type RateLimitRule = {
  windowSec: number; // hits window
  maxAttempts: number; // max hits within window
  blockSec: number; // how long to block after exceed
};

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

function clamp(n: number, min: number, max: number): number {
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

function safeJsonBody(req: Request): Record<string, unknown> {
  const b = (req as unknown as { body?: unknown }).body;
  return typeof b === 'object' && b !== null
    ? (b as Record<string, unknown>)
    : {};
}

function pickAuditActionByPath(path: string): AuditAction {
  if (path.endsWith('/password/reset/request'))
    return 'PASSWORD_RESET_REQUESTED';
  if (path.endsWith('/password/reset/confirm'))
    return 'PASSWORD_RESET_COMPLETED';
  if (path.endsWith('/verify-email/request')) return 'EMAIL_VERIFY_REQUESTED';
  if (path.endsWith('/verify-email/confirm')) return 'EMAIL_VERIFIED';
  // fallback: treat as security-ish token endpoint
  return 'AUTH_LOGIN';
}

@Injectable()
export class TokenRateLimitGuard implements CanActivate {
  constructor(
    private readonly redisService: RedisService,
    private readonly audit: AuditService,
  ) {}

  private ruleFor(path: string): RateLimitRule {
    // Defaults tuned for abuse-resistance.
    // You can override via ENV per endpoint.
    if (path.endsWith('/verify-email/request')) {
      return {
        windowSec: envInt('TOKEN_VERIFY_EMAIL_WINDOW_SEC', 10 * 60),
        maxAttempts: envInt('TOKEN_VERIFY_EMAIL_MAX', 3),
        blockSec: envInt('TOKEN_VERIFY_EMAIL_BLOCK_SEC', 30 * 60),
      };
    }

    if (path.endsWith('/password/reset/request')) {
      return {
        windowSec: envInt('TOKEN_PASSWORD_RESET_WINDOW_SEC', 10 * 60),
        maxAttempts: envInt('TOKEN_PASSWORD_RESET_MAX', 5),
        blockSec: envInt('TOKEN_PASSWORD_RESET_BLOCK_SEC', 30 * 60),
      };
    }

    // Confirm endpoints (bruteforce token protection)
    if (path.endsWith('/verify-email/confirm')) {
      return {
        windowSec: envInt('TOKEN_VERIFY_EMAIL_CONFIRM_WINDOW_SEC', 10 * 60),
        maxAttempts: envInt('TOKEN_VERIFY_EMAIL_CONFIRM_MAX', 10),
        blockSec: envInt('TOKEN_VERIFY_EMAIL_CONFIRM_BLOCK_SEC', 30 * 60),
      };
    }

    if (path.endsWith('/password/reset/confirm')) {
      return {
        windowSec: envInt('TOKEN_PASSWORD_RESET_CONFIRM_WINDOW_SEC', 10 * 60),
        maxAttempts: envInt('TOKEN_PASSWORD_RESET_CONFIRM_MAX', 10),
        blockSec: envInt('TOKEN_PASSWORD_RESET_CONFIRM_BLOCK_SEC', 30 * 60),
      };
    }

    // fallback
    return { windowSec: 60, maxAttempts: 60, blockSec: 60 };
  }

  private identifierHashFor(req: Request): string | undefined {
    const path = req.path ?? '';
    const body = safeJsonBody(req);

    // request reset uses identifier
    if (path.endsWith('/password/reset/request')) {
      const identifier =
        typeof body.identifier === 'string' ? body.identifier : '';
      const norm = identifier.trim().toLowerCase();
      if (!norm) return undefined;
      const toHash = norm.includes('@') ? normalizeEmail(norm) : norm;
      return sha256Hex(toHash);
    }

    // verify-email/request optionally includes email
    if (path.endsWith('/verify-email/request')) {
      const email = typeof body.email === 'string' ? body.email : '';
      const norm = email.trim();
      if (!norm) return undefined;
      return sha256Hex(normalizeEmail(norm));
    }

    // confirm endpoints: hash the token itself (do NOT store raw)
    if (
      path.endsWith('/verify-email/confirm') ||
      path.endsWith('/password/reset/confirm')
    ) {
      const token = typeof body.token === 'string' ? body.token : '';
      const norm = token.trim();
      if (!norm) return undefined;
      return sha256Hex(norm);
    }

    return undefined;
  }

  private buildKey(req: Request): {
    key: string;
    ip: string;
    userId?: string;
    identifierHash?: string;
    prefix: string;
  } {
    const prefix =
      (process.env.TOKEN_RATE_LIMIT_PREFIX ?? 'tokrl').trim() || 'tokrl';
    const ip = resolveIp(req) ?? '0.0.0.0';
    const path = (req.path ?? 'unknown').replace(/\s+/g, '');

    const userId = (req as unknown as { user?: { id?: string } }).user?.id;
    const identifierHash = this.identifierHashFor(req);

    // Keying strategy: ip + identifierHash + userId (where possible)
    const key = [prefix, path, ip, identifierHash ?? '-', userId ?? '-'].join(
      ':',
    );
    return { key, ip, userId, identifierHash, prefix };
  }

  private async auditRateLimited(input: {
    req: Request;
    action: AuditAction;
    actorId?: string | null;
    ip: string | null;
    identifierHash?: string | null;
    path: string;
    retryAfterSec: number;
    hits?: number;
    windowTtlSec?: number;
    phase: 'request' | 'confirm';
  }) {
    await this.audit.log({
      severity: 'SECURITY',
      action: input.action,
      actorId: input.actorId ?? null,
      ip: input.ip,
      userAgent: readHeaderString(input.req, 'user-agent') ?? null,
      meta: {
        result: 'rate_limited',
        phase: input.phase,
        path: input.path,
        retryAfterSec: input.retryAfterSec,
        hits: input.hits ?? undefined,
        windowTtlSec: input.windowTtlSec ?? undefined,
        identifierHash: input.identifierHash ?? null,
      },
    });
  }

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    const req = ctx.switchToHttp().getRequest<Request>();
    const res = ctx.switchToHttp().getResponse<Response>();
    const redis = this.redisService.redis;

    const path = req.path ?? '';
    const rule = this.ruleFor(path);
    const action = pickAuditActionByPath(path);

    const { key, ip, userId, identifierHash } = this.buildKey(req);
    const hitsKey = `${key}:hits`;
    const blockKey = `${key}:block`;

    // 1) blocked?
    const blockTtl = await redis.ttl(blockKey);
    if (blockTtl > 0) {
      res.setHeader('Retry-After', String(blockTtl));

      await this.auditRateLimited({
        req,
        action,
        actorId: userId ?? null,
        ip: ip ?? null,
        identifierHash: identifierHash ?? null,
        path,
        retryAfterSec: blockTtl,
        phase: path.endsWith('/confirm') ? 'confirm' : 'request',
      });

      throw new HttpException(
        { ok: false, error: 'RATE_LIMITED', retryAfterSec: blockTtl },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    // 2) incr hits + ttl
    const multi = redis.multi();
    multi.incr(hitsKey);
    multi.ttl(hitsKey);
    const out = await multi.exec();

    // fail-open (don’t DoS auth if Redis hiccups)
    if (!out) return true;

    const hitsRaw = out[0]?.[1];
    const ttlRaw = out[1]?.[1];

    const hits = typeof hitsRaw === 'number' ? hitsRaw : Number(hitsRaw ?? 1);
    let ttl = typeof ttlRaw === 'number' ? ttlRaw : Number(ttlRaw ?? -1);

    const windowSec = clamp(rule.windowSec, 1, 24 * 3600);
    const blockSec = clamp(rule.blockSec, 1, 24 * 3600);

    if (hits === 1 || ttl === -1 || ttl === -2) {
      await redis.expire(hitsKey, windowSec);
      ttl = windowSec;
    }

    // 3) exceeded?
    if (hits > rule.maxAttempts) {
      await redis.set(blockKey, '1', 'EX', blockSec);

      res.setHeader('Retry-After', String(blockSec));

      await this.auditRateLimited({
        req,
        action,
        actorId: userId ?? null,
        ip: ip ?? null,
        identifierHash: identifierHash ?? null,
        path,
        retryAfterSec: blockSec,
        hits,
        windowTtlSec: ttl,
        phase: path.endsWith('/confirm') ? 'confirm' : 'request',
      });

      throw new HttpException(
        { ok: false, error: 'RATE_LIMITED', retryAfterSec: blockSec },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }

    return true;
  }
}
