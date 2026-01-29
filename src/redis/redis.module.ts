import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { RedisService } from './redis.service';
import { REDIS_CLIENT } from './redis.constants';

@Module({
  providers: [
    {
      provide: REDIS_CLIENT,
      useFactory: async () => {
        const redis = new Redis({
          host: process.env.REDIS_HOST || 'localhost',
          port: parseInt(process.env.REDIS_PORT || '6379'),
          retryStrategy: (times) => {
            const delay = Math.min(times * 50, 2000);
            return delay;
          },
          // Use lazyConnect so that Redis does not attempt to connect on client
          // instantiation. We connect explicitly below and rely on retryStrategy
          // to handle subsequent reconnection attempts without blocking module init.
          lazyConnect: true,
        });

        redis.on('connect', () => {
          console.log('✓ Redis connected');
        });

        redis.on('error', (err) => {
          console.error('✗ Redis connection error:', err.message);
        });

        redis.on('reconnecting', () => {
          console.log('↻ Redis reconnecting...');
        });

        try {
          await redis.connect();
        } catch (err) {
          const message = err instanceof Error ? err.message : String(err);
          const stack = err instanceof Error ? err.stack : undefined;
          console.error(
            `✗ Initial Redis connection failed: ${message}. Retrying with configured strategy (backoff up to 2000ms).`,
          );
          if (stack) {
            console.error(stack);
          }
          // Return instance anyway - retryStrategy will handle reconnection
        }

        return redis;
      },
    },
    RedisService,
  ],
  exports: [REDIS_CLIENT, RedisService],
})
export class RedisModule {}
