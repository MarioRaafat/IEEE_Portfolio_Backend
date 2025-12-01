import {
    BadRequestException,
    Body,
    Controller,
    Get,
    InternalServerErrorException,
    Param,
    Post,
    Query,
    Req,
    Res,
    UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import type { Request, Response } from 'express';
import {
    ApiBearerAuth,
    ApiBody,
    ApiCookieAuth,
    ApiCreatedResponse,
    ApiOkResponse,
    ApiOperation,
    ApiParam,
    ApiQuery,
    ApiResponse,
    ApiTags,
} from '@nestjs/swagger';
import {
    ApiBadRequestErrorResponse,
    ApiConflictErrorResponse,
    ApiForbiddenErrorResponse,
    ApiInternalServerError,
    ApiNotFoundErrorResponse,
    ApiUnauthorizedErrorResponse,
    ApiUnprocessableEntityErrorResponse,
} from 'src/decorators/swagger-error-responses.decorator';
import { ERROR_MESSAGES, SUCCESS_MESSAGES } from 'src/constants/swagger-messages';
import {
    login_swagger,
} from './auth.swagger';
import { LoginDTO } from './dto';
import { ResponseMessage } from 'src/decorators/response-message.decorator';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
    constructor(private readonly auth_service: AuthService) {}

    private httpOnlyRefreshToken(response: Response, refresh: string) {
        const is_production = process.env.NODE_ENV === 'production';

        response.cookie('refresh_token', refresh, {
            httpOnly: true,
            secure: true,
            sameSite: is_production ? 'strict' : 'none',
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
    }

    @ApiOperation(login_swagger.operation)
    @ApiBody({ type: LoginDTO })
    @ApiOkResponse(login_swagger.responses.success)
    @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.WRONG_PASSWORD)
    @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
    @ApiForbiddenErrorResponse(ERROR_MESSAGES.EMAIL_NOT_VERIFIED)
    @ResponseMessage(SUCCESS_MESSAGES.LOGGED_IN)
    @Post('login')
    async login(@Body() login_dto: LoginDTO, @Res({ passthrough: true }) response: Response) {
        const { access_token, refresh_token, user } = await this.auth_service.login(login_dto);

        this.httpOnlyRefreshToken(response, refresh_token);
        return { access_token, user };
    }
}
