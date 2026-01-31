export const REDIS_CLIENT = 'REDIS_CLIENT';

export enum RedisKeyPrefix {
  RefreshToken = 'refresh_token',
  EmailVerificationOtp = 'email_otp',
  PasswordResetOtp = 'password_otp',
}
