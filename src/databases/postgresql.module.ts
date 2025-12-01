import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { existsSync, readFileSync } from 'fs';

@Module({
    imports: [
        ConfigModule,
        TypeOrmModule.forRootAsync({
            imports: [ConfigModule],
            inject: [ConfigService],
            useFactory: (config_service: ConfigService) => {
                // SSL CONFIG
                let ssl: any;

                const ca_path = process.env.DATABASE_CA;

                if (ca_path) {
                    if (existsSync(ca_path)) {
                        ssl = {
                            ca: readFileSync(ca_path).toString(),
                        };
                    }
                }

                return {
                    type: 'postgres',
                    host: config_service.get<string>('POSTGRES_HOST'),
                    username: config_service.get<string>('POSTGRES_USERNAME'),
                    password: config_service.get<string>('POSTGRES_PASSWORD'),
                    database: config_service.get<string>('POSTGRES_DB'),
                    port: config_service.get<number>('POSTGRES_PORT'),
                    synchronize: false, // Using migrations instead
                    autoLoadEntities: true,

                    ssl,
                };
            },
        }),
    ],
    providers: [ConfigService],
})
export class PostgreSQLModule {}
