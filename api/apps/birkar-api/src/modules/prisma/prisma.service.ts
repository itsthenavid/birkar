import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '@prisma/client';
import { Pool, type Pool as PoolType } from 'pg';

function requireEnv(name: string): string {
  const v = process.env[name];
  if (typeof v !== 'string' || v.trim() === '') {
    throw new Error(`${name} is missing`);
  }
  return v;
}

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private pool?: PoolType;

  constructor() {
    const url = process.env.DATABASE_URL?.trim();

    const finalUrl = url && url.length > 0 ? url : requireEnv('DATABASE_URL');

    const pool = new Pool({ connectionString: finalUrl });
    const adapter = new PrismaPg(pool);

    super({ adapter });

    this.pool = pool;
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
    await this.pool?.end();
  }
}
