import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request } from 'express';

type AuthedRequest = Request & { user?: { id: string } };

@Injectable()
export class SessionGuard implements CanActivate {
  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<AuthedRequest>();
    if (!req.user?.id) throw new UnauthorizedException('Unauthorized');
    return true;
  }
}
