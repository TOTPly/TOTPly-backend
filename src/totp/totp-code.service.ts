import { Injectable } from '@nestjs/common';
import { TOTP, NobleCryptoPlugin, ScureBase32Plugin, createGuardrails } from 'otplib';

@Injectable()
export class TotpCodeService {
  private totp: InstanceType<typeof TOTP>;

  constructor() {
    this.totp = new TOTP({
      crypto: new NobleCryptoPlugin(),
      base32: new ScureBase32Plugin(),
      guardrails: createGuardrails({ MIN_SECRET_BYTES: 1 }),
    });
  }

  async generate(secret: string, algorithm: string, digits: number, period: number): Promise<{ code: string; remainingSeconds: number; period: number; serverTime: number }> {
    const code = await this.totp.generate({ secret, algorithm: algorithm.toLowerCase() as 'sha1' | 'sha256' | 'sha512', digits, period });
    const now = Math.floor(Date.now() / 1000);
    const remainingSeconds = period - (now % period);

    return { code, remainingSeconds, period, serverTime: now };
  }
}
