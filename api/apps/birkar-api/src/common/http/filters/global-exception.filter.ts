// src/common/http/filters/global-exception.filter.ts
import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { ZodError } from 'zod';

import { Prisma } from '@prisma/client';

import type { ApiErrorBody, ErrorCode } from '../http-error.codes';
import { getRequestId } from '../request-id';

type UnknownRecord = Record<string, unknown>;

function isRecord(v: unknown): v is UnknownRecord {
  return typeof v === 'object' && v !== null;
}

function isString(v: unknown): v is string {
  return typeof v === 'string';
}

function buildError(input: {
  code: ErrorCode;
  message: string;
  details?: unknown;
  requestId?: string;
}): ApiErrorBody {
  return {
    ok: false,
    error: {
      code: input.code,
      message: input.message,
      details: input.details,
    },
    meta: input.requestId ? { requestId: input.requestId } : undefined,
  };
}

function codeFromHttpStatus(status: number): ErrorCode {
  if (status === 401) return 'UNAUTHORIZED';
  if (status === 403) return 'FORBIDDEN';
  if (status === 404) return 'NOT_FOUND';
  if (status === 409) return 'CONFLICT';
  if (status === 429) return 'RATE_LIMITED';
  if (status >= 500) return 'INTERNAL_ERROR';
  return 'BAD_REQUEST';
}

function isPrismaKnownError(
  e: unknown,
): e is Prisma.PrismaClientKnownRequestError {
  // ✅ no any member access
  if (!isRecord(e)) return false;
  return isString(e['code']) && isString(e['clientVersion']);
}

function normalizeHttpExceptionPayload(payload: unknown): {
  message?: string;
  errorCodeHint?: ErrorCode;
  details?: unknown;
} {
  // Nest may return string | object
  if (isString(payload)) {
    return { message: payload, details: payload };
  }

  if (!isRecord(payload)) {
    return { details: payload };
  }

  const ok = payload['ok'];
  const error = payload['error'];
  const message = payload['message'];

  // Your guards sometimes throw: { ok:false, error:'RATE_LIMITED', retryAfterSec }
  if (ok === false && isString(error) && error === 'RATE_LIMITED') {
    return {
      message: 'Rate limited',
      errorCodeHint: 'RATE_LIMITED',
      details: payload,
    };
  }

  // Or: { ok:false, error:{ code:'...', message:'...' } }
  if (ok === false && isRecord(error)) {
    const innerCode = error['code'];
    const innerMessage = error['message'];

    const hint =
      isString(innerCode) && (innerCode as ErrorCode)
        ? (innerCode as ErrorCode)
        : undefined;

    return {
      message: isString(innerMessage)
        ? innerMessage
        : isString(message)
          ? message
          : undefined,
      errorCodeHint: hint,
      details: payload,
    };
  }

  return {
    message: isString(message) ? message : undefined,
    details: payload,
  };
}

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const req = ctx.getRequest<Request>();
    const res = ctx.getResponse<Response>();
    const requestId = getRequestId(req);

    // 1) Zod validation -> 400
    if (exception instanceof ZodError) {
      res.status(HttpStatus.BAD_REQUEST).json(
        buildError({
          code: 'VALIDATION_ERROR',
          message: 'Validation failed',
          details: exception.issues,
          requestId,
        }),
      );
      return;
    }

    // 2) Prisma -> 409 for unique, else 400
    if (isPrismaKnownError(exception)) {
      if (exception.code === 'P2002') {
        res.status(HttpStatus.CONFLICT).json(
          buildError({
            code: 'CONFLICT',
            message: 'Unique constraint failed',
            details: exception.meta ?? undefined,
            requestId,
          }),
        );
        return;
      }

      res.status(HttpStatus.BAD_REQUEST).json(
        buildError({
          code: 'BAD_REQUEST',
          message: 'Database error',
          details: { code: exception.code, meta: exception.meta ?? undefined },
          requestId,
        }),
      );
      return;
    }

    // 3) HttpException -> keep status, normalize body
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const payload = exception.getResponse();

      const norm = normalizeHttpExceptionPayload(payload);

      res.status(status).json(
        buildError({
          code: norm.errorCodeHint ?? codeFromHttpStatus(status),
          message: norm.message ?? exception.message ?? 'Request failed',
          details: norm.details,
          requestId,
        }),
      );
      return;
    }

    // 4) Unknown -> 500
    res.status(HttpStatus.INTERNAL_SERVER_ERROR).json(
      buildError({
        code: 'INTERNAL_ERROR',
        message: 'Internal server error',
        requestId,
      }),
    );
  }
}
