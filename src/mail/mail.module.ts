import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import type SMTPTransport from 'nodemailer/lib/smtp-transport';
import { MailService } from './mail.service';

const MAIL_TRANSPORTER = 'MAIL_TRANSPORTER';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: MAIL_TRANSPORTER,
      useFactory: (config: ConfigService) => {
        const transportOptions: SMTPTransport.Options = {
          host: config.get('GMAIL_SMTP_HOST'),
          port: config.get('GMAIL_SMTP_PORT'),
          secure: config.get<boolean>('GMAIL_SMTP_SECURE'),
          auth: {
            user: config.get('GMAIL_SMTP_LOGIN'),
            pass: config.get('GMAIL_SMTP_PASSWORD'),
          },
        };

        const defaults = {
          from: `"${config.get('GMAIL_EMAIL_FROM_NAME')}" <${config.get('GMAIL_EMAIL_FROM_ADDRESS')}>`,
        };

        return nodemailer.createTransport(transportOptions, defaults);
      },
      inject: [ConfigService],
    },
    MailService,
  ],
  exports: [MailService],
})
export class MailModule {}
