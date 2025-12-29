import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';

import { AppModule } from '../../src/app.module';
import { getServer } from '../utils/supertest';

describe('AppController (e2e)', () => {
  let app: INestApplication | undefined;

  beforeAll(async () => {
    const moduleFixture = await Test.createTestingModule({
      imports: [AppModule],
    }).compile();

    app = moduleFixture.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  it('GET /health -> 200', async () => {
    await request(getServer(app!)).get('/health').expect(200);
  });
});
