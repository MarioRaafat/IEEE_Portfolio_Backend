import { IsEmail, IsOptional, IsString } from 'class-validator';

export class GithubOAuthDto {
  @IsEmail()
  email: string;

  @IsString()
  name: string;

  @IsOptional()
  @IsString()
  avatar_url?: string;

  @IsString()
  github_id: string;
}
