import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDTO, RegisterDTO } from './dto';
import { User } from './interfaces/user.interface';
import { OtpRecord } from './interfaces/otpRecord.interface';
import { ERROR_MESSAGES } from 'src/constants/swagger-messages';
import * as bcrypt from 'bcrypt';
import { StringValue } from 'ms';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    // TODO:
    // private readonly user_repository: UserRepository,
    private readonly jwt_service: JwtService,
    // private readonly redis_service: RedisService,
  ) {}

  // Dev-only in-memory user store. Replace with a real repository when DB entities are available.
  private users: User[] = [];

  // OTP Records Storage for now till we implement Redis
  otpRecords: OtpRecord[] = [];

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
        secret: process.env.JWT_TOKEN_SECRET ?? 'fallback-secret', // Optional: Add fallback for safety
        expiresIn: (process.env.JWT_TOKEN_EXPIRATION_TIME ??
          '1h') as StringValue,
      },
    );

    const refresh_payload = { id: user_id, jti: crypto.randomUUID() };
    const refresh_token = this.jwt_service.sign(refresh_payload, {
      secret: process.env.JWT_REFRESH_SECRET ?? 'fallback-refresh-secret',
      expiresIn: (process.env.JWT_REFRESH_EXPIRATION_TIME ??
        '7d') as StringValue,
    });

    // TODO: store refresh token in redis

    return {
      access_token: access_token,
      refresh_token: refresh_token,
    };
  }

  async validateUserPassword(id: string, password: string): Promise<User> {
    // Promise<User> { --> DON'T FORGET TO CHANGE IT
    // TODO: make user repository and user entity
    const user = this.users.find((u) => u.id === id) ?? null;
    // const user = await this.user_repository.findById(id);

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
      user = this.users.find((u) => u.email === identifier) ?? null;
    } else {
      identifier_type = 'username';
      user = this.users.find((u) => u.username === identifier) ?? null;
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
      user: instanceToPlain(user),
      access_token: access_token,
      refresh_token: refresh_token,
    };
  }

  async register(register_dto: RegisterDTO): Promise<User> {
    const { email, username, password, confirmPassword } = register_dto as any;

    if (password !== confirmPassword) {
      throw new BadRequestException(
        ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH,
      );
    }

    // uniqueness checks against in-memory store (dev-only)
    const emailExists = this.users.some((u) => u.email === email);
    if (emailExists) {
      throw new BadRequestException(ERROR_MESSAGES.EMAIL_ALREADY_EXISTS);
    }

    const usernameExists = this.users.some((u) => u.username === username);
    if (usernameExists) {
      throw new BadRequestException(ERROR_MESSAGES.USERNAME_ALREADY_TAKEN);
    }

    // hash password
    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const newUser: User = {
      id: crypto.randomUUID(),
      email,
      username,
      password: passwordHash,
      isEmailVerified: false,
      createdAt: new Date().toISOString(),
    };

    this.users.push(newUser);

    return instanceToPlain(newUser);
  }

  async logout() {
    // TODO: When we add Redis, delete the refresh token for this userId here.
    // await this.redis_service.del(`refresh_token:${userId}`);

    return { success: true };
  }

  async generateOtp(email: string): Promise<{ success: boolean }> {
    // Check if user exists by email
    const user = this.users.find((u) => u.email === email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    const otp = this.generateNumericOtp(6);

    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const otpHash = await bcrypt.hash(otp, saltRounds);

    const expiresAt = Date.now() + 10 * 60 * 1000;

    const otpRecord: OtpRecord = {
      userId: user.id,
      otpHash: otpHash,
      expiresAt: expiresAt,
    };

    // Remove any existing OTP for this user
    this.otpRecords = this.otpRecords.filter((r) => r.userId !== user.id);

    // Add new OTP record
    this.otpRecords.push(otpRecord);

    // TODO: nodemailer service so that we can send OTP emails
    // For now, just a console log
    console.log(`[DEV] OTP for ${email}: ${otp} (Expires in 10 minutes)`);

    return { success: true };
  }

  async verifyOtp(email: string, otp: string): Promise<{ success: boolean }> {
    const user = this.users.find((u) => u.email === email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    const otpRecord = this.otpRecords.find((r) => r.userId === user.id);
    if (!otpRecord) {
      throw new BadRequestException(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN);
    }

    if (Date.now() > otpRecord.expiresAt) {
      this.otpRecords = this.otpRecords.filter((r) => r.userId !== user.id);
      throw new BadRequestException(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN);
    }

    const isOtpValid = await bcrypt.compare(otp, otpRecord.otpHash);
    if (!isOtpValid) {
      throw new BadRequestException(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN);
    }

    this.otpRecords = this.otpRecords.filter((r) => r.userId !== user.id);

    // TODO: Mark user email as verified in the database or generate password reset token
    user.isEmailVerified = true; // for the in-memory store logic for now

    // For now, just return success

    return { success: true };
  }
}
function instanceToPlain(user: any) {
  if (!user) return user;
  const copy = { ...user };
  if (copy.password) delete copy.password;
  return copy;
}
