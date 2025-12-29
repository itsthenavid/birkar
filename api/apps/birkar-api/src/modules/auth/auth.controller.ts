import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import { ENV } from '../../common/constants/env.constants';
import { readHeaderString, resolveIp } from '../../common/http/headers';
import { AuthRateLimitGuard } from '../../common/security/rate-limit.guard';
import { TokenRateLimitGuard } from '../../common/security/token-rate-limit.guard';
import { buildSessionCookieOptions } from '../../common/utils/cookies';

import { SessionGuard } from '../sessions/session.guard';
import { SessionsService } from '../sessions/session.service';

import { AuthService } from './auth.service';
import {
  PasswordResetConfirmSchema,
  PasswordResetRequestSchema,
  VerifyEmailConfirmSchema,
  VerifyEmailRequestSchema,
} from './dto/auth-tokens.dto';
import { LoginSchema } from './dto/login.dto';
import { RegisterSchema } from './dto/register.dto';

type RequestUser = { id: string };
type RequestSession = { id: string };

type AuthedRequest = Request & {
  user?: RequestUser;
  session?: RequestSession;
};

type AuthMeta = { ip?: string; userAgent?: string };

@Controller('/auth')
@UseGuards(AuthRateLimitGuard) // coarse baseline auth throttling
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly sessions: SessionsService,
  ) {}

  // ──────────────────────────────
  // Helpers
  // ──────────────────────────────

  private get sessionCookieName(): string {
    return process.env[ENV.SESSION_COOKIE_NAME] ?? 'sid';
  }

  private isTestEnv(): boolean {
    return (process.env.NODE_ENV ?? '').toLowerCase() === 'test';
  }

  private setSessionCookie(res: Response, token: string): void {
    res.cookie(this.sessionCookieName, token, buildSessionCookieOptions());
  }

  private clearSessionCookie(res: Response): void {
    res.clearCookie(this.sessionCookieName, buildSessionCookieOptions());
  }

  private metaFromReq(req: Request): AuthMeta {
    return {
      ip: resolveIp(req),
      userAgent: readHeaderString(req, 'user-agent'),
    };
  }

  private requireUser(req: AuthedRequest): RequestUser {
    // SessionGuard should set this; this is a safety net for type narrowing.
    if (!req.user?.id) {
      // We intentionally do NOT leak details; SessionGuard should already have 401’d.
      throw new Error(
        'Invariant violated: authenticated user missing on request',
      );
    }
    return req.user;
  }

  // ──────────────────────────────
  // Register / Login / Logout / Me
  // ──────────────────────────────

  @Post('/register')
  async register(
    @Body() body: unknown,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const dto = RegisterSchema.parse(body);

    const user = await this.auth.register(dto);

    const created = await this.sessions.createSession(
      user.id,
      this.metaFromReq(req),
    );

    this.setSessionCookie(res, created.token);
    return { ok: true, user };
  }

  @Post('/login')
  async login(
    @Body() body: unknown,
    @Req() req: AuthedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const dto = LoginSchema.parse(body);
    const meta = this.metaFromReq(req);

    const user = await this.auth.validateLocal(
      dto.identifier,
      dto.password,
      meta,
    );

    // Session rotation policy:
    // - if client asks for rotate AND a session exists, rotate it
    // - otherwise create a fresh session
    const created =
      dto.rotate && req.session?.id
        ? await this.sessions.rotateSession(req.session.id, user.id, meta)
        : await this.sessions.createSession(user.id, meta);

    this.setSessionCookie(res, created.token);
    return { ok: true };
  }

  @Post('/logout')
  @UseGuards(SessionGuard)
  async logout(
    @Req() req: AuthedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (req.session?.id) {
      await this.sessions.revokeById(req.session.id);
    }

    this.clearSessionCookie(res);
    return { ok: true };
  }

  @Get('/me')
  @UseGuards(SessionGuard)
  async me(@Req() req: AuthedRequest) {
    const userId = this.requireUser(req).id;
    const user = await this.auth.me(userId);
    return { ok: true, user };
  }

  // ──────────────────────────────
  // Verify Email
  // ──────────────────────────────

  /**
   * Requires session:
   * - avoids account enumeration
   * - allows keying by userId in TokenRateLimitGuard
   *
   * Privacy policy:
   * - In production: do NOT return token-like material
   * - In test: return token for e2e determinism
   */
  @Post('/verify-email/request')
  @UseGuards(SessionGuard, TokenRateLimitGuard)
  async requestVerifyEmail(@Body() body: unknown, @Req() req: AuthedRequest) {
    const dto = VerifyEmailRequestSchema.parse(body);

    const out = await this.auth.requestVerifyEmail({
      userId: this.requireUser(req).id,
      email: dto.email,
      meta: this.metaFromReq(req),
    });

    return this.isTestEnv() ? { ok: true, ...out } : { ok: true };
  }

  /**
   * Optional but recommended: rate-limit confirm too (brute-force token attempts)
   */
  @Post('/verify-email/confirm')
  @UseGuards(TokenRateLimitGuard)
  @HttpCode(204)
  async confirmVerifyEmail(@Body() body: unknown, @Req() req: Request) {
    const dto = VerifyEmailConfirmSchema.parse(body);

    await this.auth.confirmVerifyEmail({
      token: dto.token,
      meta: this.metaFromReq(req),
    });
  }

  // ──────────────────────────────
  // Password Reset
  // ──────────────────────────────

  /**
   * Public endpoint (no session), must be privacy-safe.
   * TokenRateLimitGuard will key using ip + identifierHash.
   *
   * Privacy policy:
   * - In production: always return {ok:true} (no enumeration)
   * - In test: return token for e2e determinism
   */
  @Post('/password/reset/request')
  @UseGuards(TokenRateLimitGuard)
  async requestPasswordReset(@Body() body: unknown, @Req() req: Request) {
    const dto = PasswordResetRequestSchema.parse(body);

    const out = await this.auth.requestPasswordReset({
      identifier: dto.identifier,
      meta: this.metaFromReq(req),
    });

    return this.isTestEnv() ? { ok: true, ...out } : { ok: true };
  }

  /**
   * Optional but recommended: rate-limit confirm too (brute-force token attempts)
   */
  @Post('/password/reset/confirm')
  @UseGuards(TokenRateLimitGuard)
  @HttpCode(204)
  async confirmPasswordReset(@Body() body: unknown, @Req() req: Request) {
    const dto = PasswordResetConfirmSchema.parse(body);

    await this.auth.confirmPasswordReset({
      token: dto.token,
      newPassword: dto.newPassword,
      meta: this.metaFromReq(req),
    });
  }
}
