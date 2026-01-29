import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { PostgreSQLModule } from './databases/postgresql.module';
import { UsersModule } from './users/users.module';
import { RolesModule } from './roles/roles.module';

@Module({
    imports: [
        ConfigModule.forRoot({
            isGlobal: true,
            envFilePath: 'config/.env',
        }),
        PostgreSQLModule,
        AuthModule,
        UsersModule,
        RolesModule
    ],
    controllers: [AppController],
    providers: [AppService],
})
export class AppModule {}
