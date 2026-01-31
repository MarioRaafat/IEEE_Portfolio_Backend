import { Injectable, ServiceUnavailableException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';
import { buildOtpEmailHtml } from './templates/otp-email.template';

@Injectable()
export class MailService {
  constructor(
    private mailerService: MailerService,
    private configService: ConfigService,
  ) {}

  async sendEmail(to: string, subject: string, content: string){
    try {
      await this.mailerService.sendMail({
        to,
        subject,
        html: content,
      });
    } catch (error) {
      console.error('Error sending email:', error);
      throw new ServiceUnavailableException('Could not send email');
    }
  }

  async sendOTPEmail(to: string, otp: string): Promise<void> {
    const subject = 'Your One-Time Password (OTP)';
    const logoUrl = this.configService.get<string>('MAIL_LOGO_URL');
    const content = buildOtpEmailHtml({ otp, logoUrl: logoUrl || undefined });
    await this.sendEmail(to, subject, content);
  }
}
