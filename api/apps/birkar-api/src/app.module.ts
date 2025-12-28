import { Module } from '@nestjs/common';

import { AuthModule } from '../src/modules/auth/auth.modules';
import { RedisModule } from '../src/modules/redis/redis.module';
import { PrismaModule } from './modules/prisma/prisma.module';

import { AppController } from './app.controller';

@Module({
  imports: [RedisModule, PrismaModule, AuthModule],
  controllers: [AppController],
  providers: [],
})
export class AppModule {}
