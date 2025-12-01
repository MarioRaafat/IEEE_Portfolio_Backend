import { IsIn, IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { STRING_MAX_LENGTH } from 'src/constants/variables';

export class LoginDTO {
    @ApiProperty({
        description: 'email, or username of the user',
        example: 'mariorafat10@gmail.com',
        format: 'email',
    })
    @IsString()
    @IsNotEmpty()
    @MaxLength(STRING_MAX_LENGTH)
    identifier: string;

    @ApiProperty({
        description:
            'User password - must contain at least one uppercase letter, one lowercase letter, and one number or special character',
        example: 'Mario0o0o!#$@2252004',
        minLength: 8,
    })
    @IsNotEmpty()
    @MaxLength(STRING_MAX_LENGTH)
    password: string;
}
