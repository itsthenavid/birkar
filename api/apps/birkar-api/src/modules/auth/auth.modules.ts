import { Module } from '@nestjs/common';

import { PrismaModule } from '../prisma/prisma.module';
import { SessionsModule } from '../sessions/session.module';

import { AuditModule } from '../../common/audit/audit.module';
import { LockoutService } from '../../common/security/lockout.service';

import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

@Module({
  imports: [PrismaModule, SessionsModule, AuditModule],
  controllers: [AuthController],
  providers: [AuthService, LockoutService],
  exports: [AuthService],
})
export class AuthModule {}
