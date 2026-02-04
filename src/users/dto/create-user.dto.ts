import {
  IsEmail,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsPhoneNumber,
  IsString,
  Matches,
  Max,
  MaxLength,
  Min,
  MinLength,
  IsEnum,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';
import { RoleName } from 'src/roles/entities/role.entity';

export class CreateUserDto {
  @ApiProperty({
    description: 'Full name of the user',
    example: 'Ali Said',
    minLength: 2,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(2)
  @MaxLength(STRING_MAX_LENGTH)
  name: string;

  @ApiProperty({
    description: 'Email address of the user',
    example: 'asazizg1@gmail.com',
    format: 'email',
  })
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(STRING_MAX_LENGTH)
  email: string;

  @ApiProperty({
    description:
      'User password - must contain at least one uppercase letter, one lowercase letter, one number, and one special character, minimum length is 8 characters',
    example: 'A@lliSa_idd11',
    minLength: 8,
    maxLength: STRING_MAX_LENGTH,
    format: 'password',
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(8, { message: 'Password is too short' })
  @MaxLength(STRING_MAX_LENGTH)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
    {
      message:
        'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
    },
  )
  password: string;

  @ApiProperty({
    description: 'Name of the user role',
    example: RoleName.ADMIN,
    enum: RoleName,
  })
  @IsEnum(RoleName, {
    message: `Role must be one of the following: ${Object.values(RoleName).join(', ')}`,
  })
  @IsNotEmpty()
  role: RoleName;

  @ApiProperty({
    description: 'URL to user avatar image',
    example: 'https://example.com/avatars/AliSaid.jpg',
    required: false,
  })
  @IsString()
  @IsOptional()
  avatar_url?: string;

  @ApiProperty({
    description: 'Short biography of the user',
    example:
      'Computer Engineering student interested in AI and web development',
    required: false,
  })
  @IsString()
  @IsOptional()
  bio?: string;

  @ApiProperty({
    description: 'Phone number of the user',
    example: '+20-100-123-4567',
  })
  @IsString()
  @IsNotEmpty()
  @IsPhoneNumber('ZZ', { message: 'Phone number must be valid' })
  phone: string;

  @ApiProperty({
    description: 'Faculty or school name',
    example: 'Faculty of Engineering',
  })
  @IsString()
  @IsNotEmpty()
  faculty: string;

  @ApiProperty({
    description: 'University name',
    example: 'Cairo University',
  })
  @IsString()
  @IsNotEmpty()
  university: string;

  @ApiProperty({
    description: 'Academic year (1-5)',
    example: 3,
    minimum: 1,
    maximum: 5,
  })
  @IsInt()
  @Min(1)
  @Max(5)
  @IsNotEmpty()
  academic_year: number;

  @ApiProperty({
    description: 'Major or specialization',
    example: 'Web Development Team',
    required: false,
  })
  @IsString()
  @IsOptional()
  major?: string;
}
