import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailService } from './mail.service';

@Module({
  imports: [
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        transport: {
          host: config.get('GMAIL_SMTP_HOST'),
          port: config.get('GMAIL_SMTP_PORT'),
          secure: config.get<boolean>('GMAIL_SMTP_SECURE'),
          auth: {
            user: config.get('GMAIL_SMTP_LOGIN'),
            pass: config.get('GMAIL_SMTP_PASSWORD'),
          },
        },
        defaults: {
          from: `"${config.get('GMAIL_EMAIL_FROM_NAME')}" <${config.get('GMAIL_EMAIL_FROM_ADDRESS')}>`,
        },
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}
