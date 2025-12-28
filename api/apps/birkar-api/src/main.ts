import 'dotenv/config';

import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';

import { AppModule } from './app.module';
import { csrfMiddleware } from './common/security/csrf.middleware';
import { CsrfService } from './common/security/csrf.service';

async function bootstrap(): Promise<void> {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.set('trust proxy', 1);

  app.use(helmet());

  app.use(cookieParser(process.env.COOKIE_SECRET ?? 'dev_only_change_me'));

  const csrf = app.get(CsrfService);
  app.use(csrfMiddleware(csrf));

  app.enableCors({
    origin: process.env.CORS_ORIGIN ?? 'http://localhost:3000',
    credentials: true,
  });

  const port = Number(process.env.PORT ?? 3001);
  await app.listen(port);

  console.log(`🚀 API listening on http://localhost:${port}`);
}

void bootstrap();
