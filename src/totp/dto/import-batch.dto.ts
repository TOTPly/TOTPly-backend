import { IsArray, IsString, Matches, ArrayMinSize } from 'class-validator';

export class ImportBatchDto {
  @IsArray()
  @ArrayMinSize(1)
  @IsString({ each: true })
  @Matches(/^otpauth:\/\/totp\//, { each: true, message: 'Each URI must be a valid otpauth://totp/ URI' })
  uris: string[];
}
