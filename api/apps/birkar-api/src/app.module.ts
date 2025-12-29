// apps/birkar-api/src/app.module.ts
import { Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';

import { AppController } from './app.controller';

import { SecurityModule } from './common/security/security.module';
import { AuthModule } from './modules/auth/auth.modules';
import { PrismaModule } from './modules/prisma/prisma.module';
import { RedisModule } from './modules/redis/redis.module';

import { PrismaExceptionFilter } from './common/filters/prisma-exception.filter';
import { ZodExceptionFilter } from './common/filters/zod-exception.filter';

import { CsrfGuard } from './common/security/csrf/csrf.guard';

@Module({
  imports: [RedisModule, PrismaModule, AuthModule, SecurityModule],
  controllers: [AppController],
  providers: [
    // ✅ Global guards
    { provide: APP_GUARD, useClass: CsrfGuard },

    // ✅ Global exception filters
    { provide: APP_FILTER, useClass: ZodExceptionFilter },
    { provide: APP_FILTER, useClass: PrismaExceptionFilter },
  ],
})
export class AppModule {}
