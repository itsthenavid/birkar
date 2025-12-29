// src/common/security/csrf/csrf.guard.ts
import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import type { Request } from 'express';

import { readHeaderString } from '../../http/headers';
import { CsrfService } from '../csrf.service';
import { csrfCookieName, csrfHeaderName } from './csrf.constants';

type CookieBag = Record<string, unknown>;

function readCookie(req: Request, name: string): string | undefined {
  const cookiesUnknown = (req as unknown as { cookies?: unknown }).cookies;
  if (typeof cookiesUnknown !== 'object' || cookiesUnknown === null)
    return undefined;
  const bag = cookiesUnknown as CookieBag;
  const v = bag[name];
  return typeof v === 'string' ? v : undefined;
}

function isSafeMethod(method: string | undefined): boolean {
  const m = (method ?? '').toUpperCase();
  return m === 'GET' || m === 'HEAD' || m === 'OPTIONS';
}

function hasBrowserSignals(req: Request): boolean {
  // CSRF فقط در کانتکست مرورگر معنی دارد
  const origin = readHeaderString(req, 'origin');
  const referer = readHeaderString(req, 'referer');
  return typeof origin === 'string' || typeof referer === 'string';
}

@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(private readonly csrf: CsrfService) {}

  canActivate(ctx: ExecutionContext): boolean {
    const req = ctx.switchToHttp().getRequest<Request>();

    // Allow safe methods
    if (isSafeMethod(req.method)) return true;

    // اگر درخواست مرورگری نبود (تست‌ها / سرور-به-سرور / کلاینت‌های API)
    // CSRF را enforce نمی‌کنیم.
    if (!hasBrowserSignals(req)) return true;

    const cookieName = csrfCookieName();
    const headerName = csrfHeaderName();

    const cookieToken = readCookie(req, cookieName);
    const headerToken = readHeaderString(req, headerName);

    if (
      typeof cookieToken !== 'string' ||
      typeof headerToken !== 'string' ||
      !this.csrf.verify(cookieToken, headerToken)
    ) {
      throw new ForbiddenException('CSRF token missing or invalid');
    }

    return true;
  }
}
