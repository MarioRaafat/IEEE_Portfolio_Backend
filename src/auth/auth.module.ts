import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { RedisModule } from 'src/redis/redis.module';
import { RolesModule } from 'src/roles/roles.module';

@Module({
  imports: [JwtModule, UsersModule, RedisModule, RolesModule],
  providers: [AuthService],
  controllers: [AuthController],
})
export class AuthModule {}
