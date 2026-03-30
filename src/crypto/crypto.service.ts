import { Injectable } from '@nestjs/common';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { InfisicalService } from '../infisical/infisical.service';

export interface EncryptedPayload {
  encryptedSecret: Uint8Array;
  iv: Uint8Array;
  authTag: Uint8Array;
  encryptedDek: Uint8Array;
  dekIv: Uint8Array;
  dekAuthTag: Uint8Array;
}

@Injectable()
export class CryptoService {
  constructor(private infisicalService: InfisicalService) {}

  private getMasterKey(): Buffer {
    return Buffer.from(process.env.MASTER_ENCRYPTION_KEY!, 'hex');
  }

  async encrypt(secret: Buffer, userId: string): Promise<EncryptedPayload> {
    const userKey = await this.infisicalService.getUserKey(userId);

    const dek = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    const encryptedSecret = Buffer.concat([cipher.update(secret), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const dekIv = randomBytes(12);
    const dekCipher = createCipheriv('aes-256-gcm', userKey, dekIv);
    const encryptedDek = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
    const dekAuthTag = dekCipher.getAuthTag();

    return {
      encryptedSecret: new Uint8Array(encryptedSecret),
      iv: new Uint8Array(iv),
      authTag: new Uint8Array(authTag),
      encryptedDek: new Uint8Array(encryptedDek),
      dekIv: new Uint8Array(dekIv),
      dekAuthTag: new Uint8Array(dekAuthTag),
    };
  }

  async decrypt(payload: EncryptedPayload, userId: string, keyVersion: number = 2): Promise<Buffer> {
    let kek: Buffer;
    if (keyVersion === 1) {
      kek = this.getMasterKey();
    } else {
      kek = await this.infisicalService.getUserKey(userId);
    }

    const dekDecipher = createDecipheriv('aes-256-gcm', kek, Buffer.from(payload.dekIv));
    dekDecipher.setAuthTag(Buffer.from(payload.dekAuthTag));
    const dek = Buffer.concat([dekDecipher.update(Buffer.from(payload.encryptedDek)), dekDecipher.final()]);

    const decipher = createDecipheriv('aes-256-gcm', dek, Buffer.from(payload.iv));
    decipher.setAuthTag(Buffer.from(payload.authTag));
    return Buffer.concat([decipher.update(Buffer.from(payload.encryptedSecret)), decipher.final()]);
  }

  decryptDekWithMasterKey(entry: { encryptedDek: Uint8Array; dekIv: Uint8Array; dekAuthTag: Uint8Array }): Buffer {
    const masterKey = this.getMasterKey();
    const dekDecipher = createDecipheriv('aes-256-gcm', masterKey, Buffer.from(entry.dekIv));
    dekDecipher.setAuthTag(Buffer.from(entry.dekAuthTag));
    return Buffer.concat([dekDecipher.update(Buffer.from(entry.encryptedDek)), dekDecipher.final()]);
  }

  encryptDekWithKey(dek: Buffer, key: Buffer): { encryptedDek: Uint8Array; dekIv: Uint8Array; dekAuthTag: Uint8Array } {
    const dekIv = randomBytes(12);
    const dekCipher = createCipheriv('aes-256-gcm', key, dekIv);
    const encryptedDek = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
    const dekAuthTag = dekCipher.getAuthTag();

    return {
      encryptedDek: new Uint8Array(encryptedDek),
      dekIv: new Uint8Array(dekIv),
      dekAuthTag: new Uint8Array(dekAuthTag),
    };
  }
}
