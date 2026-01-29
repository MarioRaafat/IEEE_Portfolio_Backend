import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDTO, RegisterDTO } from './dto';
import { ERROR_MESSAGES } from 'src/constants/swagger-messages';
import * as bcrypt from 'bcrypt';
import { StringValue } from 'ms';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { UsersRepository } from 'src/users/users.repository';
import { User } from 'src/users/entities/user.entity';
import { RedisService } from 'src/redis/redis.service';
import { RolesService } from 'src/roles/roles.service';
import { RoleName } from 'src/roles/entities/role.entity';

@Injectable()
export class AuthService {
  private readonly REDIS_REFRESH_TOKEN_PREFIX =
    process.env.REDIS_REFRESH_TOKEN_PREFIX ?? 'refresh_token';
  private readonly REDIS_OTP_PREFIX = process.env.REDIS_OTP_PREFIX ?? 'otp';
  private readonly REFRESH_TOKEN_TTL = Number(
    process.env.REDIS_REFRESH_TOKEN_TTL_SECONDS ?? 7 * 24 * 60 * 60,
  );
  private readonly OTP_TTL = Number(
    process.env.REDIS_OTP_TTL_SECONDS ?? 10 * 60,
  );

  constructor(
    private readonly user_repository: UsersRepository,
    private readonly jwt_service: JwtService,
    private readonly redisService: RedisService,
    private readonly roles_service: RolesService,
  ) {}

  // Private Helper Method to generate OTP
  private generateNumericOtp(length: number = 6): string {
    // Generates a string like "123456"
    return crypto
      .randomInt(0, Math.pow(10, length))
      .toString()
      .padStart(length, '0');
  }

  async generateTokens(user_id: string) {
    const access_token = this.jwt_service.sign(
      { id: user_id },
      {
        secret: process.env.JWT_TOKEN_SECRET ?? 'fallback-secret',
        expiresIn: (process.env.JWT_TOKEN_EXPIRATION_TIME ??
          '1h') as StringValue,
      },
    );

    const jti = crypto.randomUUID();
    const refresh_payload = { id: user_id, jti };
    const refresh_token = this.jwt_service.sign(refresh_payload, {
      secret: process.env.JWT_REFRESH_SECRET ?? 'fallback-refresh-secret',
      expiresIn: (process.env.JWT_REFRESH_EXPIRATION_TIME ??
        '7d') as StringValue,
    });

    // Store refresh token in Redis with configured TTL
    await this.redisService.setex(
      `${this.REDIS_REFRESH_TOKEN_PREFIX}:${user_id}:${jti}`,
      this.REFRESH_TOKEN_TTL,
      refresh_token,
    );

    return {
      access_token: access_token,
      refresh_token: refresh_token,
    };
  }

  async validateUserPassword(id: string, password: string): Promise<User> {
    const user = await this.user_repository.findByIdWithPassword(id);

    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    if (user.password) {
      const is_password_valid = await bcrypt.compare(password, user.password);
      if (!is_password_valid)
        throw new UnauthorizedException(ERROR_MESSAGES.WRONG_PASSWORD);
    } else {
      throw new UnauthorizedException(ERROR_MESSAGES.OAUTH_PASSWORD_NOT_SET);
    }

    return user;
  }

  async checkIdentifier(identifier: string) {
    let identifier_type: string = '';
    let user: User | null = null;

    if (identifier.includes('@')) {
      identifier_type = 'email';
      user = await this.user_repository.findByEmail(identifier);
    } else {
      identifier_type = 'username';
      user = await this.user_repository.findByUsername(identifier);
    }

    if (!user) {
      throw new NotFoundException(
        identifier_type === 'email'
          ? ERROR_MESSAGES.EMAIL_NOT_FOUND
          : ERROR_MESSAGES.USERNAME_NOT_FOUND,
      );
    }

    return {
      identifier_type: identifier_type,
      user_id: user.id,
    };
  }

  async login(login_dto: LoginDTO) {
    const { identifier, password } = login_dto;
    const { user_id, identifier_type } = await this.checkIdentifier(identifier);
    const user = await this.validateUserPassword(user_id, password);

    const { access_token, refresh_token } = await this.generateTokens(user_id);

    return {
      user: user,
      access_token: access_token,
      refresh_token: refresh_token,
    };
  }

  async register(register_dto: RegisterDTO): Promise<User> {
    const {
      email,
      username,
      password,
      confirmPassword,
      name,
      faculty,
      university,
      academic_year,
    } = register_dto as any;

    if (password !== confirmPassword) {
      throw new BadRequestException(
        ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH,
      );
    }

    const emailExists = await this.user_repository.findByEmail(email);
    if (emailExists) {
      throw new BadRequestException(ERROR_MESSAGES.EMAIL_ALREADY_EXISTS);
    }

    const usernameExists = await this.user_repository.findByUsername(username);
    if (usernameExists) {
      throw new BadRequestException(ERROR_MESSAGES.USERNAME_ALREADY_TAKEN);
    }

    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const visitorRole = await this.roles_service.findByName(RoleName.VISITOR);

    const newUser = await this.user_repository.create({
      email,
      username,
      name,
      password: passwordHash,
      role_id: visitorRole.id,
      faculty,
      university,
      academic_year,
      verified_email: false,
      // Add other required fields with defaults as needed
    });

    return newUser;
  }

  async logout(refresh_token?: string) {
    if (!refresh_token) {
      return { success: true };
    }

    let payload: { id?: string; jti?: string } | null = null;
    try {
      payload = this.jwt_service.verify(refresh_token, {
        secret: process.env.JWT_REFRESH_SECRET ?? 'fallback-refresh-secret',
      });
    } catch {
      throw new UnauthorizedException(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN);
    }

    if (payload?.id && payload?.jti) {
      await this.redisService.del(
        `${this.REDIS_REFRESH_TOKEN_PREFIX}:${payload.id}:${payload.jti}`,
      );
    }

    return { success: true };
  }

  async generateOtp(email: string): Promise<{ success: boolean }> {
    const user = await this.user_repository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    const otp = this.generateNumericOtp(6);

    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const otpHash = await bcrypt.hash(otp, saltRounds);

    // Store OTP in Redis with configured TTL
    const otpData = JSON.stringify({ otpHash: otpHash, userId: user.id });

    await this.redisService.setex(
      `${this.REDIS_OTP_PREFIX}:${user.id}`,
      this.OTP_TTL,
      otpData,
    );

    // TODO: nodemailer service so that we can send OTP emails
    // For now, just a console log
    console.log(`[DEV] OTP for ${email}: ${otp} (Expires in 10 minutes)`);

    return { success: true };
  }

  async verifyOtp(email: string, otp: string): Promise<{ success: boolean }> {
    const user = await this.user_repository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    // Retrieve OTP record from Redis
    const otpDataString = await this.redisService.get(
      `${this.REDIS_OTP_PREFIX}:${user.id}`,
    );
    if (!otpDataString) {
      throw new BadRequestException(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN);
    }

    const otpRecord = JSON.parse(otpDataString);

    const isOtpValid = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isOtpValid) {
      throw new BadRequestException(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN);
    }

    // Delete OTP from Redis after successful verification
    await this.redisService.del(`${this.REDIS_OTP_PREFIX}:${user.id}`);

    await this.user_repository.update(user.id, { verified_email: true });

    return { success: true };
  }
}
