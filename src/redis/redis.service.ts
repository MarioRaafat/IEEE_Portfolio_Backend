import { Inject, Injectable } from '@nestjs/common';
import { REDIS_CLIENT } from './redis.constants';
import Redis from 'ioredis';

@Injectable()
export class RedisService {
  constructor(@Inject(REDIS_CLIENT) private readonly client: Redis) {}

  async setex(
    key: string,
    seconds: number,
    value: string,
  ): Promise<'OK' | null> {
    return this.client.setex(key, seconds, value);
  }

  async get(key: string): Promise<string | null> {
    return this.client.get(key);
  }

  async del(key: string): Promise<number> {
    return this.client.del(key);
  }

  async set(key: string, value: string): Promise<'OK' | null> {
    return this.client.set(key, value);
  }

  async exists(key: string): Promise<number> {
    return this.client.exists(key);
  }

  async ttl(key: string): Promise<number> {
    return this.client.ttl(key);
  }
}
