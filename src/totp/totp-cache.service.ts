import { Injectable, Inject } from '@nestjs/common';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';

@Injectable()
export class TotpCacheService {
  constructor(@Inject(CACHE_MANAGER) private cacheManager: Cache) {}

  async get<T>(key: string): Promise<T | undefined> {
    return this.cacheManager.get<T>(key);
  }

  async set(key: string, value: any, ttl: number): Promise<void> {
    await this.cacheManager.set(key, value, ttl);
  }

  async invalidateForUser(userId: string, entryId?: string): Promise<void> {
    await this.cacheManager.del(`totp:list:${userId}`);
    if (entryId) {
      await this.cacheManager.del(`totp:detail:${userId}:${entryId}`);
      await this.cacheManager.del(`totp:uri:${userId}:${entryId}`);
      await this.cacheManager.del(`totp:qr:${userId}:${entryId}`);
    }
  }

  listKey(userId: string) { return `totp:list:${userId}`; }
  detailKey(userId: string, id: string) { return `totp:detail:${userId}:${id}`; }
  uriKey(userId: string, id: string) { return `totp:uri:${userId}:${id}`; }
  qrKey(userId: string, id: string) { return `totp:qr:${userId}:${id}`; }
}
