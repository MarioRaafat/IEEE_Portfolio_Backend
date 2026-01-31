import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { LoginDTO, RegisterDTO } from './dto';
import { GoogleOAuthDto } from './dto/google-oauth.dto';
import { CompleteOAuthProfileDto } from './dto/complete-oauth-profile.dto';
import { ERROR_MESSAGES } from 'src/constants/swagger-messages';
import * as bcrypt from 'bcrypt';
import { StringValue } from 'ms';
import * as crypto from 'crypto';
import { JwtService } from '@nestjs/jwt';
import { UsersRepository } from 'src/users/users.repository';
import { User } from 'src/users/entities/user.entity';
import { RedisService } from 'src/redis/redis.service';
import { RedisKeyPrefix } from 'src/redis/redis.constants';
import { RolesService } from 'src/roles/roles.service';
import { RoleName } from 'src/roles/entities/role.entity';
import { MailService } from 'src/mail/mail.service';

enum AuthOtpPurpose {
  EmailVerification = 'emailVerification',
  PasswordReset = 'passwordReset',
}

@Injectable()
export class AuthService {
  private readonly REDIS_REFRESH_TOKEN_PREFIX =
    process.env.REDIS_REFRESH_TOKEN_PREFIX ?? RedisKeyPrefix.RefreshToken;
  private readonly REDIS_EMAIL_OTP_PREFIX =
    process.env.REDIS_EMAIL_OTP_PREFIX ?? RedisKeyPrefix.EmailVerificationOtp;
  private readonly REDIS_PASSWORD_OTP_PREFIX =
    process.env.REDIS_PASSWORD_OTP_PREFIX ?? RedisKeyPrefix.PasswordResetOtp;
  private readonly REDIS_REFRESH_TOKEN_SET_PREFIX =
    process.env.REDIS_REFRESH_TOKEN_SET_PREFIX ?? 'refresh_token_set';
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
    private readonly mailerService: MailService,
  ) {}

  // Private Helper Method to generate OTP
  private generateNumericOtp(length: number = 6): string {
    // Generates a string like "123456"
    return crypto
      .randomInt(0, Math.pow(10, length))
      .toString()
      .padStart(length, '0');
  }

  private getOtpPrefix(purpose: AuthOtpPurpose): string {
    return purpose === AuthOtpPurpose.PasswordReset
      ? this.REDIS_PASSWORD_OTP_PREFIX
      : this.REDIS_EMAIL_OTP_PREFIX;
  }

  private getRefreshTokenSetKey(user_id: string): string {
    return `${this.REDIS_REFRESH_TOKEN_SET_PREFIX}:${user_id}`;
  }

  private async revokeAllRefreshTokens(user_id: string): Promise<void> {
    const setKey = this.getRefreshTokenSetKey(user_id);
    const keys = await this.redisService.smembers(setKey);

    await this.redisService.deleteKeys(keys);
    await this.redisService.del(setKey);
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
    const refreshKey = `${this.REDIS_REFRESH_TOKEN_PREFIX}:${user_id}:${jti}`;
    await this.redisService.setex(
      refreshKey,
      this.REFRESH_TOKEN_TTL,
      refresh_token,
    );
    await this.redisService.sadd(
      this.getRefreshTokenSetKey(user_id),
      refreshKey,
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
      const refreshKey = `${this.REDIS_REFRESH_TOKEN_PREFIX}:${payload.id}:${payload.jti}`;
      await this.redisService.del(refreshKey);
      await this.redisService.srem(
        this.getRefreshTokenSetKey(payload.id),
        refreshKey,
      );
    }

    return { success: true };
  }

  private async generateOtp(
    email: string,
    purpose: AuthOtpPurpose,
  ): Promise<{ success: boolean }> {
    const user = await this.user_repository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    if (purpose === AuthOtpPurpose.EmailVerification && user.verified_email) {
      throw new BadRequestException(ERROR_MESSAGES.ACCOUNT_ALREADY_VERIFIED);
    }

    const otp = this.generateNumericOtp(6);

    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const otpHash = await bcrypt.hash(otp, saltRounds);

    // Store OTP in Redis with configured TTL
    const otpData = JSON.stringify({ otpHash: otpHash, userId: user.id });
    const otp_prefix = this.getOtpPrefix(purpose);

    await this.redisService.setex(
      `${otp_prefix}:${user.id}`,
      this.OTP_TTL,
      otpData,
    );

    if (purpose === AuthOtpPurpose.EmailVerification) {
      await this.mailerService.sendEmailVerificationOtp(email, otp);
    } else if (purpose === AuthOtpPurpose.PasswordReset) {
      await this.mailerService.sendPasswordResetOtp(email, otp);
    }
    // For now, just a console log
    // console.log(
    //   `[DEV] OTP for ${email} (${purpose}): ${otp} (Expires in 10 minutes)`,
    // );

    return { success: true };
  }

  private async verifyOtp(
    email: string,
    otp: string,
    purpose: AuthOtpPurpose,
  ): Promise<{ success: boolean }> {
    const user = await this.user_repository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    // Retrieve OTP record from Redis
    const otp_prefix = this.getOtpPrefix(purpose);
    const otpDataString = await this.redisService.get(
      `${otp_prefix}:${user.id}`,
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
    await this.redisService.del(`${otp_prefix}:${user.id}`);

    if (purpose === AuthOtpPurpose.EmailVerification) {
      await this.user_repository.update(user.id, { verified_email: true });
    }

    return { success: true };
  }

  async sendEmailOtpForUser(user_id: string): Promise<{ success: boolean }> {
    const user = await this.user_repository.findById(user_id);
    return this.generateOtp(user.email, AuthOtpPurpose.EmailVerification);
  }

  async verifyEmailOtpForUser(
    user_id: string,
    otp: string,
  ): Promise<{ success: boolean }> {
    const user = await this.user_repository.findById(user_id);
    return this.verifyOtp(user.email, otp, AuthOtpPurpose.EmailVerification);
  }

  async sendPasswordResetOtp(email: string): Promise<{ success: boolean }> {
    return this.generateOtp(email, AuthOtpPurpose.PasswordReset);
  }

  async resetPasswordWithOtp(
    email: string,
    otp: string,
    password: string,
    confirmPassword: string,
  ): Promise<{ success: boolean }> {
    if (password !== confirmPassword) {
      throw new BadRequestException(
        ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH,
      );
    }

    const user = await this.user_repository.findByEmail(email);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    if (user.password) {
      const isSamePassword = await bcrypt.compare(password, user.password);
      if (isSamePassword) {
        throw new BadRequestException(ERROR_MESSAGES.NEW_PASSWORD_SAME_AS_OLD);
      }
    }

    await this.verifyOtp(email, otp, AuthOtpPurpose.PasswordReset);

    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);

    await this.user_repository.update(user.id, { password: passwordHash });

    await this.revokeAllRefreshTokens(user.id);

    return { success: true };
  }

  async changePassword(
    user_id: string,
    currentPassword: string,
    password: string,
    confirmPassword: string,
  ): Promise<{ success: boolean }> {
    if (password !== confirmPassword) {
      throw new BadRequestException(
        ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH,
      );
    }

    const user = await this.user_repository.findByIdWithPassword(user_id);
    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    if (!user.password) {
      throw new UnauthorizedException(ERROR_MESSAGES.OAUTH_PASSWORD_NOT_SET);
    }

    const is_current_password_valid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!is_current_password_valid) {
      throw new UnauthorizedException(ERROR_MESSAGES.WRONG_PASSWORD);
    }

    const is_same_password = await bcrypt.compare(password, user.password);
    if (is_same_password) {
      throw new BadRequestException(ERROR_MESSAGES.NEW_PASSWORD_SAME_AS_OLD);
    }

    const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS ?? 10);
    const passwordHash = await bcrypt.hash(password, saltRounds);

    await this.user_repository.update(user.id, { password: passwordHash });

    await this.revokeAllRefreshTokens(user.id);

    return { success: true };
  }

  async validateGoogleOAuth(googleOAuthDto: GoogleOAuthDto) {
    const { google_id, email, name, picture } = googleOAuthDto;

    // Check if user with this google_id exists
    let user = await this.user_repository.findByEmail(email);

    if (user && user.google_id === google_id) {
      // User exists with same google_id, return user with tokens
      const { access_token, refresh_token } = await this.generateTokens(
        user.id,
      );
      return {
        user,
        access_token,
        refresh_token,
        needsProfileCompletion: false,
      };
    }

    // Check if email exists with different provider
    if (user) {
      throw new BadRequestException(ERROR_MESSAGES.EMAIL_ALREADY_EXISTS);
    }

    // Create new user with Google OAuth info
    const visitorRole = await this.roles_service.findByName(RoleName.VISITOR);

    const newUser = await this.user_repository.create({
      email,
      name,
      google_id,
      oauth_provider: 'google',
      avatar_url: picture || undefined,
      role_id: visitorRole.id,
      verified_email: true, // Google emails are already verified
      // Set defaults for required fields that will be completed later
      username: `user_${google_id.substring(0, 8)}`, // Generate a temporary username
      faculty: '', // Will be completed in profile completion step
      university: '', // Will be completed in profile completion step
      academic_year: 1, // Default value, will be updated later
    });

    // Generate tokens for new user but mark that profile completion is needed
    const { access_token, refresh_token } = await this.generateTokens(
      newUser.id,
    );

    return {
      user: newUser,
      access_token,
      refresh_token,
      needsProfileCompletion: true,
    };
  }

  async completeOAuthProfile(
    userId: string,
    completeProfileDto: CompleteOAuthProfileDto,
  ): Promise<User> {
    const user = await this.user_repository.findById(userId);

    if (!user) {
      throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
    }

    // Check if username is provided and is unique
    if (completeProfileDto.username) {
      const usernameExists = await this.user_repository.findByUsername(
        completeProfileDto.username,
      );
      if (usernameExists && usernameExists.id !== userId) {
        throw new BadRequestException(ERROR_MESSAGES.USERNAME_ALREADY_TAKEN);
      }
    }

    // Update user profile
    const updatedUser = await this.user_repository.update(userId, {
      faculty: completeProfileDto.faculty,
      university: completeProfileDto.university,
      academic_year: completeProfileDto.academic_year,
      ...(completeProfileDto.username && {
        username: completeProfileDto.username,
      }),
      ...(completeProfileDto.major && { major: completeProfileDto.major }),
    });

    return updatedUser;
  }
}
