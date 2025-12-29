import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import type { Request, Response } from 'express';

type PrismaErrorOut = {
  ok: false;
  error: string;
  path: string;
};

function isPrismaKnown(e: unknown): e is Prisma.PrismaClientKnownRequestError {
  return (
    typeof e === 'object' &&
    e !== null &&
    (e as { code?: unknown }).code !== undefined &&
    typeof (e as { code?: unknown }).code === 'string'
  );
}

@Catch(Prisma.PrismaClientKnownRequestError)
export class PrismaExceptionFilter implements ExceptionFilter {
  catch(exception: Prisma.PrismaClientKnownRequestError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();

    // Safe defaults (don’t leak details)
    let status = HttpStatus.BAD_REQUEST;
    let body: PrismaErrorOut = {
      ok: false,
      error: 'DB_ERROR',
      path: req.path,
    };

    // Map common Prisma codes
    // P2002: Unique constraint failed
    if (exception.code === 'P2002') {
      status = HttpStatus.CONFLICT;
      body = { ok: false, error: 'CONFLICT', path: req.path };
    }

    // P2025: Record not found (e.g. update/delete where not found)
    if (exception.code === 'P2025') {
      status = HttpStatus.NOT_FOUND;
      body = { ok: false, error: 'NOT_FOUND', path: req.path };
    }

    // If something weird happens, still return safe generic
    if (!isPrismaKnown(exception)) {
      status = HttpStatus.BAD_REQUEST;
      body = { ok: false, error: 'DB_ERROR', path: req.path };
    }

    res.status(status).json(body);
  }
}
