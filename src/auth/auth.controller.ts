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
import {
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
} from 'src/constants/swagger-messages';
import {
  login_swagger,
  logout_swagger,
  register_swagger,
  generate_otp_swagger,
  verify_otp_swagger,
} from './auth.swagger';
import { LoginDTO, RegisterDTO, GenerateOtpDTO, VerifyOtpDTO } from './dto';
import { ResponseMessage } from 'src/decorators/response-message.decorator';
import { register } from 'module';

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
  async login(
    @Body() login_dto: LoginDTO,
    @Res({ passthrough: true }) response: Response,
  ) {
    const { access_token, refresh_token, user } =
      await this.auth_service.login(login_dto);

    this.httpOnlyRefreshToken(response, refresh_token);
    return { access_token, user };
  }

  // Swagger Meassages Updated
  @ApiOperation(register_swagger.operation)
  @ApiBody({ type: RegisterDTO })
  @ApiOkResponse(register_swagger.responses.success)
  @ApiConflictErrorResponse(ERROR_MESSAGES.EMAIL_ALREADY_EXISTS)
  @ApiConflictErrorResponse(ERROR_MESSAGES.USERNAME_ALREADY_TAKEN)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH)
  @ApiInternalServerError(ERROR_MESSAGES.INTERNAL_SERVER_ERROR)
  @ResponseMessage(SUCCESS_MESSAGES.USER_REGISTERED)
  @Post('register')
  async register(@Body() register_dto: RegisterDTO) {
    const user = await this.auth_service.register(register_dto);
    return { user };
  }

  @ApiOperation(logout_swagger.operation)
  @ApiOkResponse(logout_swagger.responses.success)
  @ResponseMessage(SUCCESS_MESSAGES.LOGGED_OUT)
  @Post('logout')
  async logout(@Res({ passthrough: true }) response: Response) {
    await this.auth_service.logout();

    // Clear the refresh_token cookie
    response.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'none',
    });

    return {};
  }

  @ApiOperation(generate_otp_swagger.operation)
  @ApiBody({ type: GenerateOtpDTO })
  @ApiOkResponse(generate_otp_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ResponseMessage(SUCCESS_MESSAGES.OTP_GENERATED)
  @Post('otp/generate')
  async generateOtp(@Body() generate_otp_dto: GenerateOtpDTO) {
    await this.auth_service.generateOtp(generate_otp_dto.email);
    return {};
  }

  @ApiOperation(verify_otp_swagger.operation)
  @ApiBody({ type: VerifyOtpDTO })
  @ApiOkResponse(verify_otp_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ResponseMessage(SUCCESS_MESSAGES.OTP_VERIFIED)
  @Post('otp/verify')
  async verifyOtp(@Body() verify_otp_dto: VerifyOtpDTO) {
    await this.auth_service.verifyOtp(verify_otp_dto.email, verify_otp_dto.otp);
    return {};
  }
}
