import { IsString, Length } from 'class-validator';

export class VerifyLoginDto {
  @IsString()
  tempToken: string;

  @IsString()
  @Length(6, 6)
  code: string;
}
