import { Global, Module } from '@nestjs/common';
import { InfisicalService } from './infisical.service';

@Global()
@Module({
  providers: [InfisicalService],
  exports: [InfisicalService],
})
export class InfisicalModule {}
