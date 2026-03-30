import { Injectable, NotFoundException, ForbiddenException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CryptoService } from '../crypto/crypto.service';
import { TotpCodeService } from './totp-code.service';
import { UriParserService } from './uri-parser.service';
import { CreateTotpDto } from './dto/create-totp.dto';
import { UpdateTotpDto } from './dto/update-totp.dto';

@Injectable()
export class TotpService {
  constructor(
    private prisma: PrismaService,
    private cryptoService: CryptoService,
    private totpCodeService: TotpCodeService,
    private uriParserService: UriParserService,
  ) {}

  async create(userId: string, dto: CreateTotpDto) {
    const secretBuffer = Buffer.from(dto.secret, 'utf-8');
    const encrypted = await this.cryptoService.encrypt(secretBuffer, userId);

    const entry = await this.prisma.totpEntry.create({
      data: {
        userId,
        issuer: dto.issuer,
        accountName: dto.accountName,
        encryptedSecret: Buffer.from(encrypted.encryptedSecret),
        iv: Buffer.from(encrypted.iv),
        authTag: Buffer.from(encrypted.authTag),
        encryptedDek: Buffer.from(encrypted.encryptedDek),
        dekIv: Buffer.from(encrypted.dekIv),
        dekAuthTag: Buffer.from(encrypted.dekAuthTag),
        algorithm: dto.algorithm ?? 'SHA1',
        digits: dto.digits ?? 6,
        period: dto.period ?? 30,
        keyVersion: 2,
      },
    });

    return {
      id: entry.id,
      issuer: entry.issuer,
      accountName: entry.accountName,
      algorithm: entry.algorithm,
      digits: entry.digits,
      period: entry.period,
      createdAt: entry.createdAt,
    };
  }

  async findAll(userId: string) {
    const entries = await this.prisma.totpEntry.findMany({
      where: { userId },
      select: {
        id: true,
        issuer: true,
        accountName: true,
        algorithm: true,
        digits: true,
        period: true,
        createdAt: true,
        updatedAt: true,
      },
      orderBy: { createdAt: 'desc' },
    });

    return entries;
  }

  async findOne(userId: string, id: string) {
    const entry = await this.getOwnedEntry(userId, id);
    const secret = await this.decryptSecret(entry, userId);

    return {
      id: entry.id,
      issuer: entry.issuer,
      accountName: entry.accountName,
      secret,
      algorithm: entry.algorithm,
      digits: entry.digits,
      period: entry.period,
      createdAt: entry.createdAt,
      updatedAt: entry.updatedAt,
    };
  }

  async update(userId: string, id: string, dto: UpdateTotpDto) {
    await this.getOwnedEntry(userId, id);

    const updated = await this.prisma.totpEntry.update({
      where: { id },
      data: {
        ...(dto.issuer !== undefined && { issuer: dto.issuer }),
        ...(dto.accountName !== undefined && { accountName: dto.accountName }),
      },
      select: {
        id: true,
        issuer: true,
        accountName: true,
        algorithm: true,
        digits: true,
        period: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    return updated;
  }

  async remove(userId: string, id: string) {
    await this.getOwnedEntry(userId, id);
    await this.prisma.totpEntry.delete({ where: { id } });
    return { message: 'Entry deleted' };
  }

  async generateCode(userId: string, id: string) {
    const entry = await this.getOwnedEntry(userId, id);
    const secret = await this.decryptSecret(entry, userId);
    return this.totpCodeService.generate(secret, entry.algorithm, entry.digits, entry.period);
  }

  async generateAllCodes(userId: string) {
    const entries = await this.prisma.totpEntry.findMany({
      where: { userId },
      orderBy: { createdAt: 'desc' },
    });

    return Promise.all(
      entries.map(async (entry) => {
        const secret = await this.decryptSecret(entry, userId);
        const codeData = await this.totpCodeService.generate(secret, entry.algorithm, entry.digits, entry.period);
        return {
          id: entry.id,
          issuer: entry.issuer,
          accountName: entry.accountName,
          ...codeData,
        };
      }),
    );
  }

  async importFromUri(userId: string, uri: string) {
    const parsed = this.uriParserService.parse(uri);
    return this.create(userId, {
      issuer: parsed.issuer,
      accountName: parsed.accountName,
      secret: parsed.secret,
      algorithm: parsed.algorithm,
      digits: parsed.digits,
      period: parsed.period,
    });
  }

  async importBatch(userId: string, uris: string[]) {
    return Promise.all(uris.map((uri) => this.importFromUri(userId, uri)));
  }

  async getUri(userId: string, id: string) {
    const entry = await this.getOwnedEntry(userId, id);
    const secret = await this.decryptSecret(entry, userId);
    return {
      uri: this.uriParserService.build({
        issuer: entry.issuer,
        accountName: entry.accountName,
        secret,
        algorithm: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
      }),
    };
  }

  private async decryptSecret(
    entry: { encryptedSecret: Uint8Array; iv: Uint8Array; authTag: Uint8Array; encryptedDek: Uint8Array; dekIv: Uint8Array; dekAuthTag: Uint8Array; keyVersion: number },
    userId: string,
  ): Promise<string> {
    const buf = await this.cryptoService.decrypt(
      {
        encryptedSecret: entry.encryptedSecret,
        iv: entry.iv,
        authTag: entry.authTag,
        encryptedDek: entry.encryptedDek,
        dekIv: entry.dekIv,
        dekAuthTag: entry.dekAuthTag,
      },
      userId,
      entry.keyVersion,
    );
    return buf.toString('utf-8');
  }

  private async getOwnedEntry(userId: string, id: string) {
    const entry = await this.prisma.totpEntry.findUnique({ where: { id } });

    if (!entry) {
      throw new NotFoundException('Entry not found');
    }

    if (entry.userId !== userId) {
      throw new ForbiddenException();
    }

    return entry;
  }
}
