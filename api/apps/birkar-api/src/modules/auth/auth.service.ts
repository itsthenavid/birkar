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

// ----------------------------
// TokenPurpose resolver (runtime-safe)
// ----------------------------
function pickTokenPurpose(...keys: string[]): TokenPurpose {
  // Prisma enums are runtime objects. But TS typing might not expose index signature.
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

// Resolve your project-specific names here.
// These will work even if your enum uses different naming.
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

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly lockout: LockoutService,
  ) {}

  // ----------------------------
  // Register / Login / Me
  // ----------------------------

  async register(input: { username: string; email: string; password: string }) {
    const email = normalizeEmail(input.email);
    const username = normalizeUsername(input.username);

    const exists = await this.prisma.user.findFirst({
      where: { OR: [{ email }, { username }] },
      select: { id: true },
    });
    if (exists) {
      throw new BadRequestException('Username or email already exists');
    }

    const passwordHash = await argon2.hash(input.password, {
      type: argon2.argon2id,
    });

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
        actorId: null,
        ip: ip ?? null,
        userAgent: meta?.userAgent ?? null,
        meta: { result: 'failed', locked: s.blocked },
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    const ok = await argon2.verify(user.passwordHash, password);
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

  // ----------------------------
  // Token flows: verify email / reset password
  // ----------------------------

  private tokenTtlSeconds(purpose: TokenPurpose): number {
    if (purpose === PURPOSE_EMAIL_VERIFY) return 60 * 60; // 1 hour
    if (purpose === PURPOSE_PASSWORD_RESET) return 15 * 60; // 15 minutes
    return 15 * 60;
  }

  private now(): Date {
    return new Date();
  }

  private expiresAtFromNow(purpose: TokenPurpose): Date {
    const ttl = this.tokenTtlSeconds(purpose);
    return new Date(Date.now() + ttl * 1000);
  }

  private async revokeExistingTokens(userId: string, purpose: TokenPurpose) {
    await this.prisma.authToken.updateMany({
      where: {
        userId,
        purpose,
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: this.now() },
      },
      data: { revokedAt: this.now() },
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

        // Based on your schema errors: ip exists
        ip: input.meta?.ip ?? null,

        // If later you add userAgent to schema, add it here.
        // userAgent: input.meta?.userAgent ?? null,
      },
      select: { id: true },
    });

    return { rawToken, expiresAt };
  }

  /**
   * Consume token: validate hash match, not expired, not used/revoked, mark usedAt.
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

    // Do not reveal specifics
    if (
      !record ||
      record.purpose !== input.purpose ||
      record.usedAt ||
      record.revokedAt ||
      record.expiresAt.getTime() <= Date.now()
    ) {
      throw new BadRequestException('Invalid token');
    }

    await this.prisma.authToken.update({
      where: { tokenHash },
      data: {
        usedAt: this.now(),

        // Add consumed fields only if they exist in Prisma schema.
        // consumedIp: input.meta?.ip ?? null,
        // consumedUserAgent: input.meta?.userAgent ?? null,
      },
      select: { id: true },
    });

    return { userId: record.userId };
  }

  // -------- Verify Email --------

  async requestVerifyEmail(input: {
    userId?: string;
    email?: string;
    meta?: AuthMeta;
  }): Promise<{ token?: string }> {
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

    // privacy: if user not found or inactive, return ok
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

    // already verified: noop
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

    const { rawToken } = await this.createAuthToken({
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
      meta: { result: 'ok' },
    });

    if (process.env.NODE_ENV === 'test') {
      return { token: rawToken };
    }
    return {};
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
      data: { emailVerifiedAt: this.now() },
      select: { id: true },
    });

    // Use an existing AuditAction to avoid type mismatch
    await this.audit.log({
      severity: 'SECURITY',
      action: 'EMAIL_VERIFY_REQUESTED',
      actorId: userId,
      ip: input.meta?.ip ?? null,
      userAgent: input.meta?.userAgent ?? null,
      meta: { result: 'confirmed' },
    });
  }

  // -------- Password Reset --------

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

    // privacy: always ok
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

    const { rawToken } = await this.createAuthToken({
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
      meta: { result: 'ok' },
    });

    if (process.env.NODE_ENV === 'test') {
      return { token: rawToken };
    }
    return {};
  }

  async confirmPasswordReset(input: {
    token: string;
    newPassword: string;
    meta?: AuthMeta;
  }): Promise<void> {
    if (!input.newPassword || input.newPassword.length < 8) {
      throw new BadRequestException('Password too short');
    }

    const { userId } = await this.consumeToken({
      purpose: PURPOSE_PASSWORD_RESET,
      rawToken: input.token,
      meta: input.meta,
    });

    const passwordHash = await argon2.hash(input.newPassword, {
      type: argon2.argon2id,
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash },
      select: { id: true },
    });

    // invalidate all sessions after password reset
    await this.prisma.session.deleteMany({
      where: { userId },
    });

    await this.audit.log({
      severity: 'SECURITY',
      action: 'PASSWORD_RESET_REQUESTED',
      actorId: userId,
      ip: input.meta?.ip ?? null,
      userAgent: input.meta?.userAgent ?? null,
      meta: { result: 'confirmed', sessionsInvalidated: true },
    });
  }
}
