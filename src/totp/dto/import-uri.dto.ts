import { IsString, Matches } from 'class-validator';

export class ImportUriDto {
  @IsString()
  @Matches(/^otpauth:\/\/totp\//, { message: 'Must be a valid otpauth://totp/ URI' })
  uri: string;
}
