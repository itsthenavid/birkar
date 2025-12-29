// src/common/security/csrf/csrf.constants.ts
export const DEFAULT_CSRF_COOKIE_NAME = 'csrf';
export const DEFAULT_CSRF_HEADER_NAME = 'x-csrf-token';

export function csrfCookieName(): string {
  return (process.env.CSRF_COOKIE_NAME ?? DEFAULT_CSRF_COOKIE_NAME).trim();
}

export function csrfHeaderName(): string {
  return (process.env.CSRF_HEADER_NAME ?? DEFAULT_CSRF_HEADER_NAME).trim();
}
