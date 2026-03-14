import { IsString, IsOptional, IsIn, IsInt, Min, Max, Matches } from 'class-validator';

export class CreateTotpDto {
  @IsString()
  issuer: string;

  @IsString()
  accountName: string;

  @IsString()
  @Matches(/^[A-Z2-7]+=*$/i, { message: 'Secret must be a valid Base32 string' })
  secret: string;

  @IsOptional()
  @IsIn(['SHA1', 'SHA256', 'SHA512'])
  algorithm?: string;

  @IsOptional()
  @IsInt()
  @Min(6)
  @Max(8)
  digits?: number;

  @IsOptional()
  @IsInt()
  @Min(15)
  @Max(120)
  period?: number;
}
