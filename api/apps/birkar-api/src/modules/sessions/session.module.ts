import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';

import { PrismaModule } from '../prisma/prisma.module';

import { SessionMiddleware } from './session.middleware';
import { SessionsService } from './session.service';

@Module({
  imports: [PrismaModule],
  providers: [SessionsService, SessionMiddleware],
  exports: [SessionsService],
})
export class SessionsModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(SessionMiddleware).forRoutes('*');
  }
}
