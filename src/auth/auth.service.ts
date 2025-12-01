import { ForbiddenException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { LoginDTO } from './dto';
import { ERROR_MESSAGES } from 'src/constants/swagger-messages';
import * as bcrypt from 'bcrypt';
import { StringValue } from 'ms';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        // TODO:
        // private readonly user_repository: UserRepository,
        private readonly jwt_service: JwtService,
        // private readonly redis_service: RedisService,
    ) {}

    async generateTokens(user_id: string) {
        const access_token = this.jwt_service.sign(
            { id: user_id },
            {
                secret: process.env.JWT_TOKEN_SECRET ?? 'fallback-secret', // Optional: Add fallback for safety
                expiresIn: (process.env.JWT_TOKEN_EXPIRATION_TIME ?? '1h') as StringValue,
            }
        );

        const refresh_payload = { id: user_id, jti: crypto.randomUUID() };
        const refresh_token = this.jwt_service.sign(refresh_payload, {
            secret: process.env.JWT_REFRESH_SECRET ?? 'fallback-refresh-secret',
            expiresIn: (process.env.JWT_REFRESH_EXPIRATION_TIME ?? '7d') as StringValue,
        });

        // TODO: store refresh token in redis
        
        return {
            access_token: access_token,
            refresh_token: refresh_token,
        };
    }

    async validateUserPassword(id: string, password: string) : Promise<any> {
    // Promise<User> { --> DON'T FORGET TO CHANGE IT 
        // TODO: make user repository and user entity
        const user = {id: '', email: '', password: ''};
        // const user = await this.user_repository.findById(id);

        if (!user) {
            throw new NotFoundException(ERROR_MESSAGES.USER_NOT_FOUND);
        }

        if (user.password) {
            const is_password_valid = await bcrypt.compare(password, user.password);
            if (!is_password_valid) throw new UnauthorizedException(ERROR_MESSAGES.WRONG_PASSWORD);
        } else {
            throw new UnauthorizedException(ERROR_MESSAGES.OAUTH_PASSWORD_NOT_SET);
        }

        return user;
    }

    async checkIdentifier(identifier: string) {
        let identifier_type: string = '';
        let user = {id: '', email: '', phone_number: '', username: ''};

        if (identifier.includes('@')) {
            identifier_type = 'email';
            // user = await this.user_repository.findByEmail(identifier);
        } else {
            identifier_type = 'username';
            // user = await this.user_repository.findByUsername(identifier);
        }

        if (!user) {
            throw new NotFoundException(
                identifier_type === 'email'
                    ? ERROR_MESSAGES.EMAIL_NOT_FOUND
                      : ERROR_MESSAGES.USERNAME_NOT_FOUND
            );
        }

        return {
            identifier_type: identifier_type,
            user_id: user.id,
        };
    }

    async login(login_dto: LoginDTO) {
        const { identifier, password } = login_dto;
        const { user_id, identifier_type } = await this.checkIdentifier(identifier);
        const user = await this.validateUserPassword(user_id, password);

        const { access_token, refresh_token } = await this.generateTokens(user_id);

        return {
            user: instanceToPlain(user),
            access_token: access_token,
            refresh_token: refresh_token,
        };
    }
}
function instanceToPlain(user: any) {
    throw new Error('Function not implemented.');
}

