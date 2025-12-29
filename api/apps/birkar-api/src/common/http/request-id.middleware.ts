import { randomUUID } from 'crypto';
import type { NextFunction, Request, Response } from 'express';

export function RequestIdMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  const rid = randomUUID();

  (req as unknown as { requestId?: string }).requestId = rid;
  res.setHeader('x-request-id', rid);

  next();
}
