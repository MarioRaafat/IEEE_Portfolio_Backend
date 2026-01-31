import { Body, Controller, Patch, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import type { Request, Response } from 'express';
import {
  ApiBearerAuth,
  ApiBody,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import {
  ApiBadRequestErrorResponse,
  ApiConflictErrorResponse,
  ApiForbiddenErrorResponse,
  ApiInternalServerError,
  ApiNotFoundErrorResponse,
  ApiUnauthorizedErrorResponse,
} from 'src/decorators/swagger-error-responses.decorator';
import {
  ERROR_MESSAGES,
  SUCCESS_MESSAGES,
} from 'src/constants/swagger-messages';
import {
  login_swagger,
  logout_swagger,
  register_swagger,
  send_email_otp_swagger,
  verify_email_otp_swagger,
  send_password_reset_otp_swagger,
  reset_password_swagger,
  change_password_swagger,
} from './auth.swagger';
import { LoginDTO, RegisterDTO, GenerateOtpDTO, VerifyOtpDTO } from './dto';
import { ResetPasswordDTO } from './dto/reset-password.dto';
import { ChangePasswordDTO } from './dto/change-password.dto';
import { ResponseMessage } from 'src/decorators/response-message.decorator';
import { AuthGuard } from '@nestjs/passport';
import { User } from 'src/users/entities/user.entity';

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
  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ResponseMessage(SUCCESS_MESSAGES.LOGGED_OUT)
  @Post('logout')
  async logout(
    @Req() request: Request,
    @Res({ passthrough: true }) response: Response,
  ) {
    const refresh_token = request.cookies?.refresh_token;

    const result = await this.auth_service.logout(refresh_token);

    // Clear the refresh_token cookie
    response.clearCookie('refresh_token', {
      httpOnly: true,
      secure: true,
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'none',
    });

    return result;
  }

  @ApiOperation(send_email_otp_swagger.operation)
  @ApiBody({ type: GenerateOtpDTO })
  @ApiOkResponse(send_email_otp_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ResponseMessage(SUCCESS_MESSAGES.OTP_GENERATED)
  @Post('otp/email/send')
  async sendEmailOtp(@Body() generate_otp_dto: GenerateOtpDTO) {
    const result = await this.auth_service.generateEmailVerificationOtp(
      generate_otp_dto.email,
    );
    return result;
  }

  @ApiOperation(verify_email_otp_swagger.operation)
  @ApiBody({ type: VerifyOtpDTO })
  @ApiOkResponse(verify_email_otp_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ResponseMessage(SUCCESS_MESSAGES.EMAIL_VERIFIED)
  @Patch('otp/email/verify')
  async verifyEmailOtp(@Body() verify_otp_dto: VerifyOtpDTO) {
    const result = await this.auth_service.verifyEmailVerificationOtp(
      verify_otp_dto.email,
      verify_otp_dto.otp,
    );
    return result;
  }

  @ApiOperation(send_password_reset_otp_swagger.operation)
  @ApiBody({ type: GenerateOtpDTO })
  @ApiOkResponse(send_password_reset_otp_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ResponseMessage(SUCCESS_MESSAGES.PASSWORD_RESET_OTP_SENT)
  @Post('otp/password/send')
  async sendPasswordResetOtp(@Body() generate_otp_dto: GenerateOtpDTO) {
    return this.auth_service.generatePasswordResetOtp(generate_otp_dto.email);
  }

  @ApiOperation(reset_password_swagger.operation)
  @ApiBody({ type: ResetPasswordDTO })
  @ApiOkResponse(reset_password_swagger.responses.success)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.NEW_PASSWORD_SAME_AS_OLD)
  @ResponseMessage(SUCCESS_MESSAGES.PASSWORD_RESET)
  @Patch('password/reset')
  async resetPassword(@Body() reset_password_dto: ResetPasswordDTO) {
    const result = await this.auth_service.resetPasswordWithOtp(
      reset_password_dto.email,
      reset_password_dto.otp,
      reset_password_dto.password,
      reset_password_dto.confirmPassword,
    );
    return result;
  }

  @UseGuards(AuthGuard('jwt'))
  @ApiBearerAuth()
  @ApiOperation(change_password_swagger.operation)
  @ApiBody({ type: ChangePasswordDTO })
  @ApiOkResponse(change_password_swagger.responses.success)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.INVALID_OR_EXPIRED_TOKEN)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.PASSWORD_CONFIRMATION_MISMATCH)
  @ApiBadRequestErrorResponse(ERROR_MESSAGES.NEW_PASSWORD_SAME_AS_OLD)
  @ApiUnauthorizedErrorResponse(ERROR_MESSAGES.WRONG_PASSWORD)
  @ApiNotFoundErrorResponse(ERROR_MESSAGES.USER_NOT_FOUND)
  @ResponseMessage(SUCCESS_MESSAGES.PASSWORD_CHANGED)
  @Patch('password/change')
  async changePassword(
    @Body() change_password_dto: ChangePasswordDTO,
    @Req() req: Request & { user: User },
  ) {
    return this.auth_service.changePassword(
      req.user.id,
      change_password_dto.currentPassword,
      change_password_dto.password,
      change_password_dto.confirmPassword,
    );
  }
}
