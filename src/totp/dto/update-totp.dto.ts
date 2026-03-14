import { IsString, IsOptional } from 'class-validator';

export class UpdateTotpDto {
  @IsOptional()
  @IsString()
  issuer?: string;

  @IsOptional()
  @IsString()
  accountName?: string;
}
