// src/common/security/security.module.ts
import { Module } from '@nestjs/common';

import { CsrfService } from './csrf.service';
import { CsrfGuard } from './csrf/csrf.guard';

@Module({
  providers: [CsrfService, CsrfGuard],
  exports: [CsrfService, CsrfGuard],
})
export class SecurityModule {}
