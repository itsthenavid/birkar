import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';

import { PrismaService } from '../../modules/prisma/prisma.service';
import { DEV_IMPERSONATE_HEADER } from '../constants/headers';

type AuthedRequest = Request & { user?: { id: string } };

function readHeader(req: Request, name: string): string | null {
  const raw = req.headers[name.toLowerCase()];
  if (typeof raw === 'string') {
    const v = raw.trim();
    return v.length ? v : null;
  }
  if (Array.isArray(raw) && typeof raw[0] === 'string') {
    const v = raw[0].trim();
    return v.length ? v : null;
  }
  return null;
}

@Injectable()
export class DevImpersonateGuard implements CanActivate {
  constructor(private readonly prisma: PrismaService) {}

  async canActivate(ctx: ExecutionContext): Promise<boolean> {
    if (process.env.NODE_ENV !== 'development') {
      throw new UnauthorizedException('Dev impersonation disabled');
    }

    const req = ctx.switchToHttp().getRequest<AuthedRequest>();

    const userId = readHeader(req, DEV_IMPERSONATE_HEADER);
    if (!userId) {
      throw new UnauthorizedException(`Missing ${DEV_IMPERSONATE_HEADER}`);
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true },
    });

    if (!user) {
      throw new UnauthorizedException('Dev user not found');
    }

    req.user = { id: user.id };
    return true;
  }
}
