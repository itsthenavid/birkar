// src/common/http/http-error.codes.ts
export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'CONFLICT'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'BAD_REQUEST'
  | 'INTERNAL_ERROR';

export type ApiErrorBody = {
  ok: false;
  error: {
    code: ErrorCode;
    message: string;
    details?: unknown;
  };
  meta?: {
    requestId?: string;
  };
};

export type ApiOkBody<T = unknown> = {
  ok: true;
  data?: T;
  meta?: {
    requestId?: string;
  };
};
