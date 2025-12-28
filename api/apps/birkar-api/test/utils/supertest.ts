// src/test/utils/supertest.ts
import type { INestApplication } from '@nestjs/common';
import request from 'supertest';

export type SupertestApp = Parameters<typeof request>[0];

/**
 * single controlled cast for supertest app
 * removes @typescript-eslint/no-unsafe-argument everywhere
 */
export function getServer(app: INestApplication): SupertestApp {
  return app.getHttpServer() as SupertestApp;
}
