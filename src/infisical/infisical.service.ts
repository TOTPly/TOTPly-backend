import {
  Injectable, OnModuleInit, OnModuleDestroy,
  ServiceUnavailableException, Logger,
} from '@nestjs/common';
import { InfisicalSDK } from '@infisical/sdk';
import { randomBytes } from 'crypto';

interface CachedKey {
  key: Buffer;
  expiresAt: number;
}

@Injectable()
export class InfisicalService implements OnModuleInit, OnModuleDestroy {
  private client: InfisicalSDK;
  private keyCache = new Map<string, CachedKey>();
  private readonly logger = new Logger(InfisicalService.name);
  private readonly CACHE_TTL_MS = 5 * 60 * 1000;
  private readonly SECRET_PATH = '/user-keys';
  private cleanupInterval: ReturnType<typeof setInterval>;

  async onModuleInit() {
    this.client = new InfisicalSDK({
      siteUrl: process.env.INFISICAL_SITE_URL,
    });

    try {
      await this.client.auth().universalAuth.login({
        clientId: process.env.INFISICAL_CLIENT_ID!,
        clientSecret: process.env.INFISICAL_CLIENT_SECRET!,
      });
      this.logger.log('Authenticated with Infisical');
    } catch (error) {
      this.logger.error('Failed to authenticate with Infisical', error);
      throw error;
    }

    this.cleanupInterval = setInterval(() => this.evictExpired(), 60_000);
  }

  onModuleDestroy() {
    clearInterval(this.cleanupInterval);
    this.keyCache.clear();
  }

  async createUserKey(userId: string): Promise<Buffer> {
    const key = randomBytes(32);
    const secretName = this.secretName(userId);

    try {
      await this.client.secrets().createSecret(secretName, {
        projectId: process.env.INFISICAL_PROJECT_ID!,
        environment: process.env.INFISICAL_ENVIRONMENT!,
        secretPath: this.SECRET_PATH,
        secretValue: key.toString('hex'),
      });
    } catch (error) {
      this.logger.error(`Failed to create key for user ${userId}`, error);
      throw new ServiceUnavailableException('Key store unavailable');
    }

    this.keyCache.set(userId, { key, expiresAt: Date.now() + this.CACHE_TTL_MS });
    return key;
  }

  async getUserKey(userId: string): Promise<Buffer> {
    const cached = this.keyCache.get(userId);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.key;
    }

    try {
      const secret = await this.client.secrets().getSecret({
        secretName: this.secretName(userId),
        projectId: process.env.INFISICAL_PROJECT_ID!,
        environment: process.env.INFISICAL_ENVIRONMENT!,
        secretPath: this.SECRET_PATH,
      });

      const key = Buffer.from(secret.secretValue, 'hex');
      this.keyCache.set(userId, { key, expiresAt: Date.now() + this.CACHE_TTL_MS });
      return key;
    } catch (error) {
      this.logger.error(`Failed to get key for user ${userId}`, error);
      throw new ServiceUnavailableException('Key store unavailable');
    }
  }

  async deleteUserKey(userId: string): Promise<void> {
    try {
      await this.client.secrets().deleteSecret(this.secretName(userId), {
        projectId: process.env.INFISICAL_PROJECT_ID!,
        environment: process.env.INFISICAL_ENVIRONMENT!,
        secretPath: this.SECRET_PATH,
      });
    } catch (error) {
      this.logger.error(`Failed to delete key for user ${userId}`, error);
    }
    this.keyCache.delete(userId);
  }

  private secretName(userId: string): string {
    return `USER_KEY_${userId.replace(/-/g, '_')}`;
  }

  private evictExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.keyCache) {
      if (now >= entry.expiresAt) {
        this.keyCache.delete(key);
      }
    }
  }
}
