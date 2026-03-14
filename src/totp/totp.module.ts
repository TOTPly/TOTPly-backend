import { Module } from '@nestjs/common';
import { TotpService } from './totp.service';
import { TotpController } from './totp.controller';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [AuthModule],
  controllers: [TotpController],
  providers: [TotpService],
  exports: [TotpService],
})
export class TotpModule {}
