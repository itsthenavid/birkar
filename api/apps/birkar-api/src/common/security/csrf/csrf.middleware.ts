// src/common/security/csrf/csrf.middleware.ts
import type { NextFunction, Request, Response } from 'express';

import { readHeaderString } from '../../http/headers';
import { buildCsrfCookieOptions } from '../../utils/cookies';
import type { CsrfService } from '../csrf.service';
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

export function createCsrfCookieMiddleware(csrf: CsrfService) {
  return function csrfCookieMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): void {
    const cookieName = csrfCookieName();
    const headerName = csrfHeaderName();

    const existing = readCookie(req, cookieName);
    if (existing && existing.length > 0) return next();

    const headerToken = readHeaderString(req, headerName);
    const token =
      typeof headerToken === 'string' && headerToken.length > 0
        ? headerToken
        : csrf.generateToken();

    res.cookie(cookieName, token, buildCsrfCookieOptions());
    next();
  };
}
