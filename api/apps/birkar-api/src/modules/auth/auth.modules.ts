// src/modules/auth/auth.module.ts
import { Module } from '@nestjs/common';

import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';
import { SessionsModule } from '../sessions/session.module';

import { AuditModule } from '../../common/audit/audit.module';
import { LockoutService } from '../../common/security/lockout.service';
import { TokenRateLimitGuard } from '../../common/security/token-rate-limit.guard';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [PrismaModule, SessionsModule, AuditModule, RedisModule],
  controllers: [AuthController],
  providers: [AuthService, LockoutService, TokenRateLimitGuard],
  exports: [AuthService],
})
export class AuthModule {}
