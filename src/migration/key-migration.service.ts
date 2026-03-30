import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CryptoService } from '../crypto/crypto.service';
import { InfisicalService } from '../infisical/infisical.service';

@Injectable()
export class KeyMigrationService {
  private readonly logger = new Logger(KeyMigrationService.name);

  constructor(
    private prisma: PrismaService,
    private cryptoService: CryptoService,
    private infisicalService: InfisicalService,
  ) {}

  async migrateAll(): Promise<{ migrated: number; errors: number }> {
    const users = await this.prisma.user.findMany({ select: { id: true } });
    let migrated = 0;
    let errors = 0;

    for (const user of users) {
      try {
        await this.infisicalService.getUserKey(user.id);
      } catch {
        await this.infisicalService.createUserKey(user.id);
        this.logger.log(`Created key for user ${user.id}`);
      }

      const entries = await this.prisma.totpEntry.findMany({
        where: { userId: user.id, keyVersion: 1 },
      });

      for (const entry of entries) {
        try {
          const dek = this.cryptoService.decryptDekWithMasterKey(entry);
          const userKey = await this.infisicalService.getUserKey(user.id);
          const reEncrypted = this.cryptoService.encryptDekWithKey(dek, userKey);

          await this.prisma.totpEntry.update({
            where: { id: entry.id },
            data: {
              encryptedDek: Buffer.from(reEncrypted.encryptedDek),
              dekIv: Buffer.from(reEncrypted.dekIv),
              dekAuthTag: Buffer.from(reEncrypted.dekAuthTag),
              keyVersion: 2,
            },
          });
          migrated++;
        } catch (err) {
          this.logger.error(`Failed to migrate entry ${entry.id}`, err);
          errors++;
        }
      }
    }

    return { migrated, errors };
  }
}
