import type { NextFunction, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';

export const REQUEST_ID_HEADER = 'x-request-id';

export function requestIdMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const incoming = req.header(REQUEST_ID_HEADER);

  const requestId =
    typeof incoming === 'string' && incoming.trim().length > 0
      ? incoming.trim()
      : randomUUID();

  req.requestId = requestId;
  res.setHeader(REQUEST_ID_HEADER, requestId);
  next();
}

export function getRequestId(req: Request): string | undefined {
  return req.requestId;
}
