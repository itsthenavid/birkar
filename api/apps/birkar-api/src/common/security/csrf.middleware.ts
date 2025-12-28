import type { NextFunction, Request, Response } from 'express';
import { ENV } from '../constants/env.constants';
import { buildCsrfCookieOptions } from '../utils/cookies';
import { CsrfService } from './csrf.service';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export function csrfMiddleware(csrf: CsrfService) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const csrfCookieName = process.env[ENV.CSRF_COOKIE_NAME] ?? 'csrf';
    const csrfHeaderName = (
      process.env[ENV.CSRF_HEADER_NAME] ?? 'x-csrf-token'
    ).toLowerCase();

    // Always ensure a CSRF cookie exists (idempotent)
    const cookieToken = req.cookies?.[csrfCookieName] as string | undefined;
    if (!cookieToken) {
      const token = csrf.issueToken();
      res.cookie(csrfCookieName, token, buildCsrfCookieOptions());
    }

    // Validate for unsafe methods
    if (!SAFE_METHODS.has(req.method.toUpperCase())) {
      const cookieVal = req.cookies?.[csrfCookieName] as string | undefined;
      const headerVal = (
        req.headers[csrfHeaderName] as string | undefined
      )?.trim();

      // If missing or mismatch -> reject
      if (!cookieVal || !headerVal || cookieVal !== headerVal) {
        res.status(403).json({ error: 'CSRF_VALIDATION_FAILED' });
        return;
      }
    }

    next();
  };
}
