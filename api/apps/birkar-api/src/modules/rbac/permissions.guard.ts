import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PERMISSIONS_KEY } from './permissions.decorator';

type RequestWithAuth = Request & {
  auth?: { userId?: string; permissions?: Set<string> };
};

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(ctx: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<string[]>(
      PERMISSIONS_KEY,
      [ctx.getHandler(), ctx.getClass()],
    );

    if (!required || required.length === 0) return true;

    const req = ctx.switchToHttp().getRequest<RequestWithAuth>();
    const perms = req.auth?.permissions;

    if (!perms) throw new ForbiddenException('Missing permissions context');

    const ok = required.every((p) => perms.has(p));
    if (!ok) throw new ForbiddenException('Insufficient permissions');

    return true;
  }
}
