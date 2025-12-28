import { Module } from '@nestjs/common';
import { ThrottlerModule, seconds } from '@nestjs/throttler';

import { AppController } from './app.controller';

import { PrismaModule } from './modules/prisma/prisma.module';
import { RedisModule } from './modules/redis/redis.module';

import { AuthModule } from './modules/auth/auth.modules';

import { AuditModule } from './common/audit/audit.module';
import { LockoutService } from './common/security/lockout.service';
import { RedisThrottlerStorage } from './common/security/throttle/redis-throttler.storage';
import { RedisService } from './modules/redis/redis.service';

@Module({
  imports: [
    PrismaModule,
    RedisModule,
    AuditModule,

    // Global throttling (distributed via Redis)
    ThrottlerModule.forRootAsync({
      inject: [RedisService],
      useFactory: (redisSvc: RedisService) => ({
        throttlers: [
          // global sane defaults
          { name: 'global', ttl: seconds(60), limit: 120 },
        ],
        storage: new RedisThrottlerStorage(redisSvc.redis),
      }),
    }),

    AuthModule,
  ],
  controllers: [AppController],
  providers: [LockoutService],
})
export class AppModule {}
