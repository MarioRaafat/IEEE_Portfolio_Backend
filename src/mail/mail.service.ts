import {
  Inject,
  Injectable,
  ServiceUnavailableException,
} from '@nestjs/common';
import type { Transporter } from 'nodemailer';
import { ConfigService } from '@nestjs/config';
import {
  buildEmailVerificationHtml,
  buildPasswordResetEmailHtml,
} from './templates/otp-email.template';

@Injectable()
export class MailService {
  constructor(
    @Inject('MAIL_TRANSPORTER') private readonly transporter: Transporter,
    private configService: ConfigService,
  ) {}

  async sendEmail(to: string, subject: string, content: string) {
    try {
      await this.transporter.sendMail({
        to,
        subject,
        html: content,
      });
    } catch (error) {
      console.error('Error sending email:', error);
      throw new ServiceUnavailableException('Could not send email');
    }
  }

  async sendEmailVerificationOtp(to: string, otp: string): Promise<void> {
    const subject = 'Your Email Verification One-Time Password (OTP)';
    const logoUrl = this.configService.get<string>('MAIL_LOGO_URL');
    const content = buildEmailVerificationHtml({
      otp,
      logoUrl: logoUrl || undefined,
    });
    await this.sendEmail(to, subject, content);
  }

  async sendPasswordResetOtp(to: string, otp: string): Promise<void> {
    const subject = 'Your Password Reset One-Time Password (OTP)';
    const logoUrl = this.configService.get<string>('MAIL_LOGO_URL');
    const content = buildPasswordResetEmailHtml({
      otp,
      logoUrl: logoUrl || undefined,
    });
    await this.sendEmail(to, subject, content);
  }
}
