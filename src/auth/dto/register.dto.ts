import {
  IsEmail,
  IsInt,
  IsNotEmpty,
  IsPhoneNumber,
  IsString,
  Max,
  MaxLength,
  MinLength,
  Min,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';

export class RegisterDTO {
  @ApiProperty({ description: 'User email', example: 'wagih123@gmail.com' })
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  email: string;

  @ApiProperty({ description: 'Username', example: 'AhmedWaGiiH' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  username: string;

  @ApiProperty({ description: 'Full name', example: 'Ahmed Wagih' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  name: string;

  @ApiProperty({
    description: 'Phone number',
    example: '+20-100-123-4567',
  })
  @IsString()
  @IsNotEmpty()
  @IsPhoneNumber(undefined, { message: 'Phone number must be valid' })
  phone: string;

  @ApiProperty({ description: 'Faculty', example: 'Engineering' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  faculty: string;

  @ApiProperty({ description: 'University', example: 'Cairo University' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  university: string;

  @ApiProperty({
    description: 'Academic year',
    example: 3,
    minimum: 1,
    maximum: 10,
  })
  @IsInt()
  @Min(1)
  @Max(10)
  academic_year: number;

  @ApiProperty({
    description: 'Password',
    minLength: 8,
    example: 'StrongPassw0rd!',
  })
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(STRING_MAX_LENGTH)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain lowercase, uppercase, number, and special character',
  })
  password: string;

  @ApiProperty({
    description: 'Confirm password',
    minLength: 8,
    example: 'StrongPassw0rd!',
  })
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(STRING_MAX_LENGTH)
  @Matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/, {
    message:
      'Password must contain lowercase, uppercase, number, and special character',
  })
  confirmPassword: string;
}
