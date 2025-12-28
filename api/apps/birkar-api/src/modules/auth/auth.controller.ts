import {
  Body,
  Controller,
  Get,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import type { Request, Response } from 'express';

import { ENV } from '../../common/constants/env.constants';
import { AuthRateLimitGuard } from '../../common/security/rate-limit.guard';
import { buildSessionCookieOptions } from '../../common/utils/cookies';

import { SessionGuard } from '../sessions/session.guard';
import { SessionsService } from '../sessions/session.service';

import { AuthService } from './auth.service';
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
      ip: req.socket.remoteAddress ?? undefined,
      userAgent: req.headers['user-agent'],
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

    const user = await this.auth.validateLocal(dto.identifier, dto.password);

    const meta = {
      ip: req.socket.remoteAddress ?? undefined,
      userAgent: req.headers['user-agent'],
    };

    const created =
      dto.rotate && req.session?.id
        ? await this.sessions.rotateSession(req.session.id, user.id, meta)
        : await this.sessions.createSession(user.id, meta);

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
}
