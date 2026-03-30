import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { CryptoModule } from './crypto/crypto.module';
import { TotpModule } from './totp/totp.module';
import { ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { CacheModule } from '@nestjs/cache-manager';
import { GqlThrottlerGuard } from './common/gql-throttler.guard';
import { ComplexityPlugin } from './graphql/complexity.plugin';
import { CacheControlInterceptor } from './common/interceptors/cache-control.interceptor';
import { EtagInterceptor } from './common/interceptors/etag.interceptor';
import { InfisicalModule } from './infisical/infisical.module';
import { KeyMigrationService } from './migration/key-migration.service';

@Module({
  imports: [
    ThrottlerModule.forRoot([{
      ttl: 60000,
      limit: 10,
    }]),
    CacheModule.register({
      isGlobal: true,
      ttl: 10000,
      max: 200,
    }),
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: true,
      sortSchema: true,
      playground: true,
      csrfPrevention: false,
      path: '/graphql',
      context: ({ req }) => ({ req }),
    }),
    InfisicalModule,
    PrismaModule,
    CryptoModule,
    AuthModule,
    TotpModule,
  ],
  controllers: [AppController],
  providers: [
    {
      provide: APP_GUARD,
      useClass: GqlThrottlerGuard,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: CacheControlInterceptor,
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: EtagInterceptor,
    },
    ComplexityPlugin,
    KeyMigrationService,
  ],
})
export class AppModule {}
