// src/modules/auth/auth.controller.ts
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

type AuthedRequest = Request & {
  user?: { id: string };
  session?: { id: string };
};

@Controller('/auth')
@UseGuards(AuthRateLimitGuard)
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly sessions: SessionsService,
  ) {}

  @Post('/register')
  async register(
    @Body() body: unknown,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    const dto = RegisterSchema.parse(body);

    const user = await this.auth.register(dto);

    const created = await this.sessions.createSession(user.id, {
      ip: resolveIp(req),
      userAgent: readHeaderString(req, 'user-agent'),
    });

    const cookieName = process.env[ENV.SESSION_COOKIE_NAME] ?? 'sid';
    res.cookie(cookieName, created.token, buildSessionCookieOptions());

    return { ok: true, user };
  }

  @Post('/login')
  async login(
    @Body() body: unknown,
    @Req() req: AuthedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const dto = LoginSchema.parse(body);

    const ip = resolveIp(req);
    const userAgent = readHeaderString(req, 'user-agent');

    const user = await this.auth.validateLocal(dto.identifier, dto.password, {
      ip,
      userAgent,
    });

    const created =
      dto.rotate && req.session?.id
        ? await this.sessions.rotateSession(req.session.id, user.id, {
            ip,
            userAgent,
          })
        : await this.sessions.createSession(user.id, { ip, userAgent });

    const cookieName = process.env[ENV.SESSION_COOKIE_NAME] ?? 'sid';
    res.cookie(cookieName, created.token, buildSessionCookieOptions());

    return { ok: true };
  }

  @Post('/logout')
  @UseGuards(SessionGuard)
  async logout(
    @Req() req: AuthedRequest,
    @Res({ passthrough: true }) res: Response,
  ) {
    const cookieName = process.env[ENV.SESSION_COOKIE_NAME] ?? 'sid';

    if (req.session?.id) {
      await this.sessions.revokeById(req.session.id);
    }

    res.clearCookie(cookieName, buildSessionCookieOptions());
    return { ok: true };
  }

  @Get('/me')
  @UseGuards(SessionGuard)
  async me(@Req() req: AuthedRequest) {
    const userId = req.user!.id;
    const user = await this.auth.me(userId);
    return { ok: true, user };
  }

  // ──────────────────────────────
  // Verify Email
  // ──────────────────────────────

  @Post('/verify-email/request')
  @UseGuards(SessionGuard)
  async requestVerifyEmail(@Body() body: unknown, @Req() req: AuthedRequest) {
    const dto = VerifyEmailRequestSchema.parse(body);

    const out = await this.auth.requestVerifyEmail({
      userId: req.user!.id,
      email: dto.email,
      meta: {
        ip: resolveIp(req),
        userAgent: readHeaderString(req, 'user-agent'),
      },
    });

    return { ok: true, ...out };
  }

  @Post('/verify-email/confirm')
  @HttpCode(204)
  async confirmVerifyEmail(@Body() body: unknown, @Req() req: Request) {
    const dto = VerifyEmailConfirmSchema.parse(body);

    await this.auth.confirmVerifyEmail({
      token: dto.token,
      meta: {
        ip: resolveIp(req),
        userAgent: readHeaderString(req, 'user-agent'),
      },
    });
  }

  // ──────────────────────────────
  // Password Reset
  // ──────────────────────────────

  @Post('/password/reset/request')
  async requestPasswordReset(@Body() body: unknown, @Req() req: Request) {
    const dto = PasswordResetRequestSchema.parse(body);

    const out = await this.auth.requestPasswordReset({
      identifier: dto.identifier,
      meta: {
        ip: resolveIp(req),
        userAgent: readHeaderString(req, 'user-agent'),
      },
    });

    return { ok: true, ...out };
  }

  @Post('/password/reset/confirm')
  @HttpCode(204)
  async confirmPasswordReset(@Body() body: unknown, @Req() req: Request) {
    const dto = PasswordResetConfirmSchema.parse(body);

    await this.auth.confirmPasswordReset({
      token: dto.token,
      newPassword: dto.newPassword,
      meta: {
        ip: resolveIp(req),
        userAgent: readHeaderString(req, 'user-agent'),
      },
    });
  }
}
