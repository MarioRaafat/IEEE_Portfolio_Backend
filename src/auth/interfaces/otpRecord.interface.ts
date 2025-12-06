// Temporary OTP Record Interface until we implement Redis or a proper DB entity

export interface OtpRecord {
  userId: string;
  otpHash: string;
  expiresAt: number; // Timestamp
}
