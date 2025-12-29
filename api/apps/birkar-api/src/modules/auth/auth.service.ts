// src/modules/auth/auth.service.ts
import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import * as argon2 from 'argon2';

import { TokenPurpose } from '@prisma/client';

import { AuditService } from '../../common/audit/audit.service';
import { LockoutService } from '../../common/security/lockout.service';
import {
  looksLikeEmail,
  normalizeEmail,
  normalizeUsername,
} from '../../common/utils/normalize';
import { PrismaService } from '../prisma/prisma.service';

import {
  generateRawToken,
  hashToken,
} from '../../common/auth-tokens/auth-token.utils';

type AuthMeta = { ip?: string; userAgent?: string };

// ──────────────────────────────
// TokenPurpose resolver (runtime-safe)
// ──────────────────────────────
function pickTokenPurpose(...keys: string[]): TokenPurpose {
  const enumObj = TokenPurpose as unknown as Record<
    string,
    TokenPurpose | undefined
  >;

  for (const k of keys) {
    const v = enumObj[k];
    if (v) return v;
  }

  const available = Object.keys(enumObj).sort();
  throw new Error(
    `[AuthService] TokenPurpose enum does not contain any of: ${keys.join(', ')}. ` +
      `Available keys: ${available.join(', ')}`,
  );
}

// Resolve project-specific names (robust even if enum names differ)
const PURPOSE_EMAIL_VERIFY: TokenPurpose = pickTokenPurpose(
  'EMAIL_VERIFY',
  'VERIFY_EMAIL',
  'EMAIL_VERIFICATION',
  'EMAIL_VERIFY_REQUEST',
  'EMAIL_VERIFICATION_REQUEST',
);

const PURPOSE_PASSWORD_RESET: TokenPurpose = pickTokenPurpose(
  'PASSWORD_RESET',
  'RESET_PASSWORD',
  'PASSWORD_RESET_REQUEST',
  'PASSWORD_RESET_TOKEN',
  'RESET_PASSWORD_REQUEST',
);

// ──────────────────────────────
// Small utilities
// ──────────────────────────────
function isTestEnv(): boolean {
  return (process.env.NODE_ENV ?? '').toLowerCase() === 'test';
}

function now(): Date {
  return new Date();
}

function envInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? Math.trunc(n) : fallback;
}

function clamp(n: number, min: number, max: number): number {
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.min(max, Math.trunc(n)));
}

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly lockout: LockoutService,
  ) {}

  // ──────────────────────────────
  // Password hashing
  // ──────────────────────────────

  private async hashPassword(password: string): Promise<string> {
    // Reasonable secure defaults; keep adjustable via ENV for CI/low-memory envs
    const timeCost = clamp(envInt('ARGON2_TIME_COST', 3), 1, 10);
    const memoryCost = clamp(
      envInt('ARGON2_MEMORY_COST_KIB', 64 * 1024),
      8 * 1024,
      512 * 1024,
    ); // 8MiB..512MiB
    const parallelism = clamp(envInt('ARGON2_PARALLELISM', 1), 1, 8);

    return argon2.hash(password, {
      type: argon2.argon2id,
      timeCost,
      memoryCost,
      parallelism,
    });
  }

  private async verifyPassword(
    hash: string,
    password: string,
  ): Promise<boolean> {
    // argon2.verify is timing-safe for the hash compare internally
    return argon2.verify(hash, password);
  }

  // ──────────────────────────────
  // Register / Login / Me
  // ──────────────────────────────

  async register(input: { username: string; email: string; password: string }) {
    const email = normalizeEmail(input.email);
    const username = normalizeUsername(input.username);

    // Pre-check for nice UX (Prisma unique filter is global anyway)
    const exists = await this.prisma.user.findFirst({
      where: { OR: [{ email }, { username }] },
      select: { id: true },
    });
    if (exists) {
      throw new BadRequestException('Username or email already exists');
    }

    const passwordHash = await this.hashPassword(input.password);

    const user = await this.prisma.user.create({
      data: {
        email,
        username,
        passwordHash,
        status: 'ACTIVE',
        profile: { create: { displayName: username, isPublic: true } },
      },
      select: { id: true, email: true, username: true },
    });

    // Best-effort role attach (don’t fail registration if roles table not seeded)
    const role = await this.prisma.role.findUnique({
      where: { name: 'USER' },
      select: { id: true },
    });

    if (role) {
      await this.prisma.userRole.upsert({
        where: { userId_roleId: { userId: user.id, roleId: role.id } },
        update: {},
        create: { userId: user.id, roleId: role.id, assignedBy: user.id },
      });
    }

    await this.audit.log({
      severity: 'SECURITY',
      action: 'AUTH_REGISTER',
      actorId: user.id,
      meta: { method: 'local' },
    });

    return user;
  }

  async validateLocal(identifier: string, password: string, meta?: AuthMeta) {
    const normalized = identifier.trim().toLowerCase();
    const ip = meta?.ip;
    const LOCK_PREFIX = 'login';

    const block = await this.lockout.check(LOCK_PREFIX, normalized, ip);
    if (block.blocked) {
      await this.audit.log({
        severity: 'SECURITY',
        action: 'AUTH_LOGIN',
        actorId: null,
        ip: ip ?? null,
        userAgent: meta?.userAgent ?? null,
        meta: { result: 'blocked', retryAfterSec: block.retryAfterSec },
      });
      // don’t reveal lockout
      throw new UnauthorizedException('Invalid credentials');
    }

    const user = await this.prisma.user.findFirst({
      where: looksLikeEmail(normalized)
        ? { email: normalizeEmail(normalized) }
        : { username: normalizeUsername(normalized) },
      select: { id: true, passwordHash: true, status: true },
    });

    if (!user || !user.passwordHash || user.status !== 'ACTIVE') {
      const s = await this.lockout.onFailure(LOCK_PREFIX, normalized, ip);

      await this.audit.log({
        severity: 'SECURITY',
        action: 'AUTH_LOGIN',
        actorId: user?.id ?? null,
        ip: ip ?? null,
        userAgent: meta?.userAgent ?? null,
        meta: { result: 'failed', locked: s.blocked },
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    const ok = await this.verifyPassword(user.passwordHash, password);
    if (!ok) {
      const s = await this.lockout.onFailure(LOCK_PREFIX, normalized, ip);

      await this.audit.log({
        severity: 'SECURITY',
        action: 'AUTH_LOGIN',
        actorId: user.id,
        ip: ip ?? null,
        userAgent: meta?.userAgent ?? null,
        meta: { result: 'failed', locked: s.blocked },
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    await this.lockout.onSuccess(LOCK_PREFIX, normalized, ip);

    await this.audit.log({
      severity: 'SECURITY',
      action: 'AUTH_LOGIN',
      actorId: user.id,
      ip: ip ?? null,
      userAgent: meta?.userAgent ?? null,
      meta: { result: 'ok' },
    });

    return { id: user.id };
  }

  async me(userId: string) {
    return this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        username: true,
        emailVerifiedAt: true,
        status: true,
        profile: {
          select: {
            displayName: true,
            location: true,
            website: true,
            isPublic: true,
          },
        },
      },
    });
  }

  // ──────────────────────────────
  // Token flows: verify email / reset password
  // ──────────────────────────────

  private tokenTtlSeconds(purpose: TokenPurpose): number {
    // Allow overrides via ENV for ops flexibility
    if (purpose === PURPOSE_EMAIL_VERIFY) {
      return clamp(
        envInt('TOKEN_EMAIL_VERIFY_TTL_SEC', 60 * 60),
        60,
        7 * 24 * 3600,
      );
    }
    if (purpose === PURPOSE_PASSWORD_RESET) {
      return clamp(
        envInt('TOKEN_PASSWORD_RESET_TTL_SEC', 15 * 60),
        60,
        24 * 3600,
      );
    }
    return 15 * 60;
  }

  private expiresAtFromNow(purpose: TokenPurpose): Date {
    const ttl = this.tokenTtlSeconds(purpose);
    return new Date(Date.now() + ttl * 1000);
  }

  private async revokeExistingTokens(userId: string, purpose: TokenPurpose) {
    // Enforces "max active tokens per user/purpose" == 1 (or effectively 0..1)
    await this.prisma.authToken.updateMany({
      where: {
        userId,
        purpose,
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: now() },
      },
      data: { revokedAt: now() },
    });
  }

  /**
   * Create token row (hash stored), return raw token (for email/tests).
   */
  private async createAuthToken(input: {
    userId: string;
    purpose: TokenPurpose;
    meta?: AuthMeta;
  }): Promise<{ rawToken: string; expiresAt: Date }> {
    const rawToken = generateRawToken();
    const tokenHash = hashToken(rawToken);
    const expiresAt = this.expiresAtFromNow(input.purpose);

    await this.revokeExistingTokens(input.userId, input.purpose);

    await this.prisma.authToken.create({
      data: {
        userId: input.userId,
        purpose: input.purpose,
        tokenHash,
        expiresAt,
        ip: input.meta?.ip ?? null,
      },
      select: { id: true },
    });

    return { rawToken, expiresAt };
  }

  /**
   * Consume token:
   * - Validate tokenHash exists
   * - Ensure purpose matches
   * - Ensure not expired / not used / not revoked
   * - Mark usedAt (best-effort atomicity using conditional update)
   */
  private async consumeToken(input: {
    purpose: TokenPurpose;
    rawToken: string;
    meta?: AuthMeta;
  }): Promise<{ userId: string }> {
    const tokenHash = hashToken(input.rawToken);

    const record = await this.prisma.authToken.findUnique({
      where: { tokenHash },
      select: {
        userId: true,
        purpose: true,
        expiresAt: true,
        usedAt: true,
        revokedAt: true,
      },
    });

    // Always generic error (no token oracle)
    if (
      !record ||
      record.purpose !== input.purpose ||
      record.usedAt ||
      record.revokedAt ||
      record.expiresAt.getTime() <= Date.now()
    ) {
      throw new BadRequestException('Invalid token');
    }

    // Conditional update reduces race (two requests using same token)
    const updated = await this.prisma.authToken.updateMany({
      where: {
        tokenHash,
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: now() },
        purpose: input.purpose,
      },
      data: { usedAt: now() },
    });

    if (updated.count !== 1) {
      throw new BadRequestException('Invalid token');
    }

    return { userId: record.userId };
  }

  // ──────────────────────────────
  // Verify Email
  // ──────────────────────────────

  async requestVerifyEmail(input: {
    userId?: string;
    email?: string;
    meta?: AuthMeta;
  }): Promise<{ token?: string }> {
    // Prefer userId (session-based) to avoid enumeration
    let user: {
      id: string;
      emailVerifiedAt: Date | null;
      status: string;
    } | null = null;

    if (input.userId) {
      user = await this.prisma.user.findUnique({
        where: { id: input.userId },
        select: { id: true, emailVerifiedAt: true, status: true },
      });
    } else if (input.email) {
      const email = normalizeEmail(input.email);
      user = await this.prisma.user.findUnique({
        where: { email },
        select: { id: true, emailVerifiedAt: true, status: true },
      });
    } else {
      throw new BadRequestException('Email required');
    }

    // privacy-safe NOOP
    if (!user || user.status !== 'ACTIVE') {
      await this.audit.log({
        severity: 'SECURITY',
        action: 'EMAIL_VERIFY_REQUESTED',
        actorId: input.userId ?? null,
        ip: input.meta?.ip ?? null,
        userAgent: input.meta?.userAgent ?? null,
        meta: { result: 'noop' },
      });
      return {};
    }

    // already verified => NOOP
    if (user.emailVerifiedAt) {
      await this.audit.log({
        severity: 'SECURITY',
        action: 'EMAIL_VERIFY_REQUESTED',
        actorId: user.id,
        ip: input.meta?.ip ?? null,
        userAgent: input.meta?.userAgent ?? null,
        meta: { result: 'already_verified' },
      });
      return {};
    }

    const { rawToken, expiresAt } = await this.createAuthToken({
      userId: user.id,
      purpose: PURPOSE_EMAIL_VERIFY,
      meta: input.meta,
    });

    await this.audit.log({
      severity: 'SECURITY',
      action: 'EMAIL_VERIFY_REQUESTED',
      actorId: user.id,
      ip: input.meta?.ip ?? null,
      userAgent: input.meta?.userAgent ?? null,
      meta: {
        result: 'ok',
        purpose: String(PURPOSE_EMAIL_VERIFY),
        expiresAt: expiresAt.toISOString(),
      },
    });

    return isTestEnv() ? { token: rawToken } : {};
  }

  async confirmVerifyEmail(input: {
    token: string;
    meta?: AuthMeta;
  }): Promise<void> {
    const { userId } = await this.consumeToken({
      purpose: PURPOSE_EMAIL_VERIFY,
      rawToken: input.token,
      meta: input.meta,
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { emailVerifiedAt: now() },
      select: { id: true },
    });

    await this.audit.log({
      severity: 'SECURITY',
      action: 'EMAIL_VERIFIED',
      actorId: userId,
      ip: input.meta?.ip ?? null,
      userAgent: input.meta?.userAgent ?? null,
      meta: { result: 'ok' },
    });
  }

  // ──────────────────────────────
  // Password Reset
  // ──────────────────────────────

  async requestPasswordReset(input: {
    identifier: string;
    meta?: AuthMeta;
  }): Promise<{ token?: string }> {
    const normalized = input.identifier.trim().toLowerCase();

    const user = await this.prisma.user.findFirst({
      where: looksLikeEmail(normalized)
        ? { email: normalizeEmail(normalized) }
        : { username: normalizeUsername(normalized) },
      select: { id: true, status: true },
    });

    // privacy-safe NOOP
    if (!user || user.status !== 'ACTIVE') {
      await this.audit.log({
        severity: 'SECURITY',
        action: 'PASSWORD_RESET_REQUESTED',
        actorId: null,
        ip: input.meta?.ip ?? null,
        userAgent: input.meta?.userAgent ?? null,
        meta: { result: 'noop' },
      });
      return {};
    }

    const { rawToken, expiresAt } = await this.createAuthToken({
      userId: user.id,
      purpose: PURPOSE_PASSWORD_RESET,
      meta: input.meta,
    });

    await this.audit.log({
      severity: 'SECURITY',
      action: 'PASSWORD_RESET_REQUESTED',
      actorId: user.id,
      ip: input.meta?.ip ?? null,
      userAgent: input.meta?.userAgent ?? null,
      meta: {
        result: 'ok',
        purpose: String(PURPOSE_PASSWORD_RESET),
        expiresAt: expiresAt.toISOString(),
      },
    });

    return isTestEnv() ? { token: rawToken } : {};
  }

  async confirmPasswordReset(input: {
    token: string;
    newPassword: string;
    meta?: AuthMeta;
  }): Promise<void> {
    // Minimal sanity; detailed password policy should be in DTO schema
    if (!input.newPassword || input.newPassword.length < 8) {
      throw new BadRequestException('Password too short');
    }

    const { userId } = await this.consumeToken({
      purpose: PURPOSE_PASSWORD_RESET,
      rawToken: input.token,
      meta: input.meta,
    });

    const passwordHash = await this.hashPassword(input.newPassword);

    // Make the update + session invalidation consistent
    await this.prisma.$transaction(async (tx) => {
      await tx.user.update({
        where: { id: userId },
        data: { passwordHash },
        select: { id: true },
      });

      // Invalidate all sessions after password reset
      await tx.session.deleteMany({ where: { userId } });
    });

    await this.audit.log({
      severity: 'SECURITY',
      action: 'PASSWORD_RESET_COMPLETED',
      actorId: userId,
      ip: input.meta?.ip ?? null,
      userAgent: input.meta?.userAgent ?? null,
      meta: { result: 'ok', sessionsInvalidated: true },
    });
  }
}
