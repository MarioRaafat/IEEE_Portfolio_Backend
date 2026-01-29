import { IsEmail, IsNotEmpty, Length, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';

export class VerifyOtpDTO {
  @ApiProperty({
    description: 'Email address',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  email: string;

  @ApiProperty({
    description: 'OTP code (6 digits)',
    example: '123456',
  })
  @IsNotEmpty()
  @Length(6, 6)
  otp: string;
}
