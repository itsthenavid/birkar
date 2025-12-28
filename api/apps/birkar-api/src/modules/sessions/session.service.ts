import { Injectable } from '@nestjs/common';
import { randomToken, sha256Hex } from '../../common/utils/crypto';
import { PrismaService } from '../prisma/prisma.service';

function ttlDays(): number {
  const raw = process.env.SESSION_TTL_DAYS;
  const n = raw ? Number(raw) : Number.NaN;
  return Number.isFinite(n) && n > 0 ? n : 30;
}

@Injectable()
export class SessionsService {
  constructor(private readonly prisma: PrismaService) {}

  async createSession(
    userId: string,
    meta?: { ip?: string; userAgent?: string | string[] | undefined },
  ): Promise<{ token: string; sessionId: string; expiresAt: Date }> {
    const token = randomToken(32);
    const tokenHash = sha256Hex(token);

    const expiresAt = new Date(Date.now() + ttlDays() * 24 * 60 * 60 * 1000);

    const ua =
      typeof meta?.userAgent === 'string'
        ? meta.userAgent
        : Array.isArray(meta?.userAgent)
          ? meta?.userAgent.join(' ')
          : undefined;

    const session = await this.prisma.session.create({
      data: {
        userId,
        tokenHash,
        expiresAt,
        ip: meta?.ip ?? null,
        userAgent: ua ?? null,
      },
      select: { id: true, expiresAt: true },
    });

    return { token, sessionId: session.id, expiresAt: session.expiresAt };
  }

  async rotateSession(
    oldSessionId: string,
    userId: string,
    meta?: { ip?: string; userAgent?: string | string[] | undefined },
  ): Promise<{ token: string; sessionId: string; expiresAt: Date }> {
    const next = await this.createSession(userId, meta);

    await this.prisma.session.update({
      where: { id: next.sessionId },
      data: { rotatedFromSessionId: oldSessionId },
    });

    await this.prisma.session.update({
      where: { id: oldSessionId },
      data: { revokedAt: new Date() },
    });

    return next;
  }

  async findActiveByToken(rawToken: string): Promise<{
    id: string;
    userId: string;
    expiresAt: Date;
  } | null> {
    const tokenHash = sha256Hex(rawToken);
    const now = new Date();

    return this.prisma.session.findFirst({
      where: {
        tokenHash,
        revokedAt: null,
        expiresAt: { gt: now },
      },
      select: { id: true, userId: true, expiresAt: true },
    });
  }

  async touch(sessionId: string): Promise<void> {
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { lastSeenAt: new Date() },
    });
  }

  async revokeById(sessionId: string): Promise<void> {
    await this.prisma.session.update({
      where: { id: sessionId },
      data: { revokedAt: new Date() },
    });
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }
}
