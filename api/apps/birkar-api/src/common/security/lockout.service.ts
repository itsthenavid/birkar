// src/common/security/lockout.service.ts
import { Injectable } from '@nestjs/common';
import { RedisService } from '../../modules/redis/redis.service';

export type LockoutStatus = {
  blocked: boolean;
  retryAfterSec: number;
};

@Injectable()
export class LockoutService {
  constructor(private readonly redisService: RedisService) {}

  private key(prefix: string, identifier: string, ip?: string) {
    const ipPart = ip ? `:${ip}` : '';
    return `lockout:${prefix}:${identifier}${ipPart}`;
  }

  private blockKey(prefix: string, identifier: string, ip?: string) {
    const ipPart = ip ? `:${ip}` : '';
    return `lockout:${prefix}:${identifier}${ipPart}:block`;
  }

  /**
   * Read current lockout state
   */
  async check(
    prefix: string,
    identifier: string,
    ip?: string,
  ): Promise<LockoutStatus> {
    const redis = this.redisService.redis;

    const bKey = this.blockKey(prefix, identifier, ip);
    const ttl = await redis.ttl(bKey);

    if (ttl > 0) return { blocked: true, retryAfterSec: ttl };
    return { blocked: false, retryAfterSec: 0 };
  }

  /**
   * On failed attempt, increment counter and possibly block
   */
  async onFailure(
    prefix: string,
    identifier: string,
    ip?: string,
  ): Promise<LockoutStatus> {
    const redis = this.redisService.redis;

    // defaults (later move to config)
    const windowSec = 60; // 1 minute
    const limit = 8; // 8 attempts
    const blockSec = 10 * 60; // 10 minutes

    const key = this.key(prefix, identifier, ip);
    const bKey = this.blockKey(prefix, identifier, ip);

    const blockTtl = await redis.ttl(bKey);
    if (blockTtl > 0) return { blocked: true, retryAfterSec: blockTtl };

    const multi = redis.multi();
    multi.incr(key);
    multi.ttl(key);

    const res = await multi.exec();

    // fail-open
    if (!res) return { blocked: false, retryAfterSec: 0 };

    const hitsRaw = res[0]?.[1];
    const ttlRaw = res[1]?.[1];

    const hits = typeof hitsRaw === 'number' ? hitsRaw : Number(hitsRaw ?? 1);
    let ttl = typeof ttlRaw === 'number' ? ttlRaw : Number(ttlRaw ?? -1);

    if (hits === 1 || ttl === -1 || ttl === -2) {
      await redis.expire(key, windowSec);
      ttl = windowSec;
    }

    if (hits > limit) {
      await redis.set(bKey, '1', 'EX', blockSec);
      return { blocked: true, retryAfterSec: blockSec };
    }

    return { blocked: false, retryAfterSec: 0 };
  }

  /**
   * On success, reset counters
   */
  async onSuccess(
    prefix: string,
    identifier: string,
    ip?: string,
  ): Promise<void> {
    const redis = this.redisService.redis;
    await redis.del(this.key(prefix, identifier, ip));
    await redis.del(this.blockKey(prefix, identifier, ip));
  }
}
