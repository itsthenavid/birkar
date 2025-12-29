import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpStatus,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { ZodError } from 'zod';

type ZodIssueOut = {
  path: string;
  message: string;
  code?: string;
};

@Catch(ZodError)
export class ZodExceptionFilter implements ExceptionFilter {
  catch(exception: ZodError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const res = ctx.getResponse<Response>();
    const req = ctx.getRequest<Request>();

    const issues: ZodIssueOut[] = exception.issues.map((i) => ({
      path: i.path.join('.'),
      message: i.message,
      code: i.code,
    }));

    res.status(HttpStatus.BAD_REQUEST).json({
      ok: false,
      error: 'VALIDATION_ERROR',
      path: req.path,
      issues,
    });
  }
}
