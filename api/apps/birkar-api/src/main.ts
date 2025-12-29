// src/main.ts
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';

import { AppModule } from './app.module';
import { requestIdMiddleware } from './common/http/request-id';
import { CsrfService } from './common/security/csrf.service';
import { createCsrfCookieMiddleware } from './common/security/csrf/csrf.middleware';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(requestIdMiddleware);

  // ✅ must be before csrf cookie middleware
  app.use(cookieParser());

  // ✅ ensures csrf cookie exists in browser flows
  const csrf = app.get(CsrfService);
  app.use(createCsrfCookieMiddleware(csrf));

  // ... cors, filters, listen
  const port = Number(process.env.PORT ?? 3000);
  await app.listen(port);
}

void bootstrap();
