import { Injectable, OnModuleDestroy } from '@nestjs/common';
import IORedis, { type Redis } from 'ioredis';

@Injectable()
export class RedisService implements OnModuleDestroy {
  private readonly client: Redis;

  constructor() {
    const url = process.env.REDIS_URL ?? 'redis://localhost:6379';
    this.client = new IORedis(url, {
      maxRetriesPerRequest: 2,
      enableReadyCheck: true,
      lazyConnect: false,
    });
  }

  get redis(): Redis {
    return this.client;
  }

  async onModuleDestroy(): Promise<void> {
    await this.client.quit();
  }
}
