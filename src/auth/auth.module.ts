import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from 'src/users/users.module';
import { RedisModule } from 'src/redis/redis.module';
import { RolesModule } from 'src/roles/roles.module';
import { GoogleStrategy } from './strategies/google.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { MailModule } from 'src/mail/mail.module';
@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_TOKEN_SECRET || 'fallback-secret',
      signOptions: {
        expiresIn: (process.env.JWT_TOKEN_EXPIRATION_TIME as any) || '1h',
      },
    }),
    PassportModule.register({ defaultStrategy: 'jwt' }),
    UsersModule,
    RedisModule,
    RolesModule,
    MailModule,
  ],
  providers: [AuthService, GoogleStrategy, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
