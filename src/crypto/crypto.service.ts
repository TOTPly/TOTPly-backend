import { Injectable } from '@nestjs/common';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

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
  private getMasterKey(): Buffer {
    return Buffer.from(process.env.MASTER_ENCRYPTION_KEY!, 'hex');
  }

  encrypt(secret: Buffer): EncryptedPayload {
    const masterKey = this.getMasterKey();

    const dek = randomBytes(32);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dek, iv);
    const encryptedSecret = Buffer.concat([cipher.update(secret), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const dekIv = randomBytes(12);
    const dekCipher = createCipheriv('aes-256-gcm', masterKey, dekIv);
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

  decrypt(payload: EncryptedPayload): Buffer {
    const masterKey = this.getMasterKey();

    const dekDecipher = createDecipheriv('aes-256-gcm', masterKey, Buffer.from(payload.dekIv));
    dekDecipher.setAuthTag(Buffer.from(payload.dekAuthTag));
    const dek = Buffer.concat([dekDecipher.update(Buffer.from(payload.encryptedDek)), dekDecipher.final()]);

    const decipher = createDecipheriv('aes-256-gcm', dek, Buffer.from(payload.iv));
    decipher.setAuthTag(Buffer.from(payload.authTag));
    return Buffer.concat([decipher.update(Buffer.from(payload.encryptedSecret)), decipher.final()]);
  }
}
