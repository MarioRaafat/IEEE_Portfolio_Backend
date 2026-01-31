import { ApiProperty, OmitType } from '@nestjs/swagger';
import { IsNotEmpty, MaxLength, MinLength, Matches } from 'class-validator';
import { STRING_MAX_LENGTH } from 'src/constants/variables';
import { ResetPasswordDTO } from './reset-password.dto';

export class ChangePasswordDTO extends OmitType(ResetPasswordDTO, [
  'email',
  'otp',
] as const) {
  @ApiProperty({
    description: 'Current password',
    minLength: 8,
    example: 'OldPassw0rd!',
  })
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(STRING_MAX_LENGTH)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain lowercase, uppercase, number, and special character',
  })
  currentPassword: string;
}
