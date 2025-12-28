import { Module } from '@nestjs/common';

import { AuthModule } from './modules/auth/auth.modules';
import { PrismaModule } from './modules/prisma/prisma.module';

import { AppController } from './app.controller';

@Module({
  imports: [PrismaModule, AuthModule],
  controllers: [AppController],
  providers: [],
})
export class AppModule {}
