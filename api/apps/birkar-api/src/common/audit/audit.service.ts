import { Injectable } from '@nestjs/common';
import { Prisma, type AuditAction, type AuditSeverity } from '@prisma/client';
import { PrismaService } from '../../modules/prisma/prisma.service';

type Json =
  | Prisma.InputJsonValue
  | Prisma.NullableJsonNullValueInput
  | null
  | undefined;

@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async log(input: {
    action: AuditAction;
    severity?: AuditSeverity;
    actorId?: string | null;
    targetUserId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    meta?: Prisma.InputJsonObject | Json;
    requestId?: string | null;
    traceId?: string | null;
    resourceType?: string | null;
    resourceId?: string | null;
  }): Promise<void> {
    await this.prisma.auditLog.create({
      data: {
        action: input.action,
        severity: input.severity ?? 'INFO',
        actorId: input.actorId ?? null,
        targetUserId: input.targetUserId ?? null,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
        meta: (input.meta ?? undefined) as Prisma.InputJsonValue | undefined,
        requestId: input.requestId ?? null,
        traceId: input.traceId ?? null,
        resourceType: input.resourceType ?? null,
        resourceId: input.resourceId ?? null,
      },
      select: { id: true },
    });
  }
}
