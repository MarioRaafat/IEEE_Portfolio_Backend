import { IsEmail, IsOptional, IsString } from 'class-validator';

export class GoogleOAuthDto {
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  avatar_url?: string;

  @IsString()
  google_id: string;
}
