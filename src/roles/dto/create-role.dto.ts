import {
  IsNotEmpty,
  IsString,
  MaxLength,
  MinLength,
  IsEnum,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';
import { RoleName } from '../entities/role.entity';

export class CreateRoleDto {
  @ApiProperty({
    description: 'Name of the role',
    example: RoleName.ADMIN,
    enum: RoleName,
  })
  @IsEnum(RoleName, {
    message: `Role name must be one of the following: ${Object.values(RoleName).join(', ')}`,
  })
  @IsNotEmpty()
  name: RoleName;

  @ApiProperty({
    description: 'Description of the role and its permissions',
    example: 'Administrator with full system access',
    minLength: 5,
    maxLength: STRING_MAX_LENGTH,
  })
  @IsNotEmpty()
  @IsString()
  @MinLength(5)
  @MaxLength(STRING_MAX_LENGTH)
  description: string;
}
