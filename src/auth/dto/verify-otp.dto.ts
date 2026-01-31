import { IsNotEmpty, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyOtpDTO {
  @ApiProperty({
    description: 'OTP code (6 digits)',
    example: '123456',
  })
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;
}
