import { config } from 'dotenv';
import { resolve } from 'path';
import { DataSource } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import { readFileSync } from 'fs';

config({ path: resolve(__dirname, '../../config/.env') });

const config_service = new ConfigService();

const base_config: any = {
  type: 'postgres',
  host:
    process.env.POSTGRES_HOST || config_service.get<string>('POSTGRES_HOST'),
  username:
    process.env.POSTGRES_USERNAME ||
    config_service.get<string>('POSTGRES_USERNAME'),
  password:
    process.env.POSTGRES_PASSWORD ||
    config_service.get<string>('POSTGRES_PASSWORD'),
  database:
    process.env.POSTGRES_DB || config_service.get<string>('POSTGRES_DB'),
  port:
    parseInt(process.env.POSTGRES_PORT || '5432') ||
    config_service.get<number>('POSTGRES_PORT') ||
    5432,

  entities: [
    // TODO:
    // add the entities here ya Ali
    'src/users/entities/user.entity.ts',
    'src/roles/entities/role.entity.ts',
    'src/events/entities/event.entity.ts',
    'src/events/entities/event-registration.entity.ts',
  ],

  migrations: ['src/migrations/*{.ts,.js}'],
  migrationsRun: false,
  synchronize: false,
  uuidExtension: 'pgcrypto',
};

if (process.env.DATABASE_CA) {
  base_config.ssl = {
    ca: readFileSync(process.env.DATABASE_CA).toString(),
  };
}

export default new DataSource(base_config);
