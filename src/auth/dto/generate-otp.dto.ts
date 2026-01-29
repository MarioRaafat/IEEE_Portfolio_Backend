import { IsEmail, IsNotEmpty, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';

export class GenerateOtpDTO {
  @ApiProperty({
    description: 'Email address to generate OTP for',
    example: 'user@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  email: string;
}
