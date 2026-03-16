import { Injectable, BadRequestException } from '@nestjs/common';

export interface ParsedOtpauthUri {
  issuer: string;
  accountName: string;
  secret: string;
  algorithm: string;
  digits: number;
  period: number;
}

@Injectable()
export class UriParserService {
  parse(uri: string): ParsedOtpauthUri {
    let parsed: URL;
    try {
      parsed = new URL(uri);
    } catch {
      throw new BadRequestException('Invalid otpauth URI');
    }

    if (parsed.protocol !== 'otpauth:') {
      throw new BadRequestException('URI must start with otpauth://');
    }

    if (parsed.host !== 'totp') {
      throw new BadRequestException('Only TOTP URIs are supported');
    }

    const secret = parsed.searchParams.get('secret');
    if (!secret) {
      throw new BadRequestException('Secret is required in otpauth URI');
    }

    const label = decodeURIComponent(parsed.pathname.slice(1));
    let issuer = parsed.searchParams.get('issuer') || '';
    let accountName = label;

    if (label.includes(':')) {
      const parts = label.split(':');
      issuer = issuer || parts[0].trim();
      accountName = parts.slice(1).join(':').trim();
    }

    const algorithm = (parsed.searchParams.get('algorithm') || 'SHA1').toUpperCase();
    const digits = parseInt(parsed.searchParams.get('digits') || '6', 10);
    const period = parseInt(parsed.searchParams.get('period') || '30', 10);

    return { issuer, accountName, secret: secret.toUpperCase(), algorithm, digits, period };
  }

  build(params: ParsedOtpauthUri): string {
    const label = params.issuer
      ? `${encodeURIComponent(params.issuer)}:${encodeURIComponent(params.accountName)}`
      : encodeURIComponent(params.accountName);

    const searchParams = new URLSearchParams({
      secret: params.secret,
      issuer: params.issuer,
      algorithm: params.algorithm,
      digits: params.digits.toString(),
      period: params.period.toString(),
    });

    return `otpauth://totp/${label}?${searchParams.toString()}`;
  }
}
