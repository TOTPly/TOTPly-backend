import { NestFactory } from '@nestjs/core';
import { AppModule } from '../app.module';
import { KeyMigrationService } from './key-migration.service';

async function runMigration() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const migrationService = app.get(KeyMigrationService);

  console.log('Starting key migration...');
  const result = await migrationService.migrateAll();
  console.log(`Migration complete: ${result.migrated} migrated, ${result.errors} errors`);

  await app.close();
}

runMigration();
