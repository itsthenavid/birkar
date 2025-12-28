import type { ThrottlerStorage } from '@nestjs/throttler';
import type { Redis } from 'ioredis';

type StorageRecord = {
  totalHits: number;
  timeToExpire: number;
  isBlocked: boolean;
  timeToBlockExpire: number;
};

export class RedisThrottlerStorage implements ThrottlerStorage {
  constructor(private readonly redis: Redis) {}

  private hitsKey(throttlerName: string, key: string): string {
    return `th:${throttlerName}:hits:${key}`;
  }

  private blockKey(throttlerName: string, key: string): string {
    return `th:${throttlerName}:block:${key}`;
  }

  async increment(
    key: string,
    ttl: number,
    limit: number,
    blockDuration: number,
    throttlerName: string,
  ): Promise<StorageRecord> {
    const hitsKey = this.hitsKey(throttlerName, key);
    const blockKey = this.blockKey(throttlerName, key);

    // 1) check block
    const blockTtl = await this.redis.ttl(blockKey);
    if (blockTtl > 0) {
      return {
        totalHits: limit,
        timeToExpire: 0,
        isBlocked: true,
        timeToBlockExpire: blockTtl,
      };
    }

    // 2) increment hits + ensure ttl
    const multi = this.redis.multi();
    multi.incr(hitsKey);
    multi.ttl(hitsKey);

    const res = await multi.exec();

    // fail-open
    if (!res) {
      return {
        totalHits: 1,
        timeToExpire: ttl,
        isBlocked: false,
        timeToBlockExpire: 0,
      };
    }

    const hitsRaw = res[0]?.[1];
    const ttlRaw = res[1]?.[1];

    const totalHits =
      typeof hitsRaw === 'number' ? hitsRaw : Number(hitsRaw ?? 1);

    let timeToExpire =
      typeof ttlRaw === 'number' ? ttlRaw : Number(ttlRaw ?? -1);

    if (totalHits === 1 || timeToExpire === -1 || timeToExpire === -2) {
      await this.redis.expire(hitsKey, ttl);
      timeToExpire = ttl;
    }

    // 3) if exceeded -> block
    if (totalHits > limit) {
      await this.redis.set(blockKey, '1', 'EX', blockDuration);
      return {
        totalHits,
        timeToExpire,
        isBlocked: true,
        timeToBlockExpire: blockDuration,
      };
    }

    return {
      totalHits,
      timeToExpire,
      isBlocked: false,
      timeToBlockExpire: 0,
    };
  }
}
