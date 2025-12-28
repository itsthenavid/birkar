import { Injectable, NestMiddleware } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import { ENV } from '../../common/constants/env.constants';
import { SessionsService } from './session.service';

export type AuthedRequest = Request & {
  user?: { id: string };
  session?: { id: string };
};

function readCookie(req: Request, name: string): string | null {
  const raw = req.headers.cookie;
  if (!raw) return null;

  const parts = raw.split(';').map((p) => p.trim());
  const hit = parts.find((p) => p.startsWith(`${name}=`));
  if (!hit) return null;

  const value = hit.slice(name.length + 1);
  return value ? decodeURIComponent(value) : null;
}

@Injectable()
export class SessionMiddleware implements NestMiddleware {
  constructor(private readonly sessions: SessionsService) {}

  async use(
    req: AuthedRequest,
    _res: Response,
    next: NextFunction,
  ): Promise<void> {
    const cookieName = process.env[ENV.SESSION_COOKIE_NAME] ?? 'sid';
    const token = readCookie(req, cookieName);

    if (!token) {
      next();
      return;
    }

    const active = await this.sessions.findActiveByToken(token);

    if (!active) {
      next();
      return;
    }

    req.user = { id: active.userId };
    req.session = { id: active.id };

    void this.sessions.touch(active.id).catch(() => undefined);

    next();
  }
}
