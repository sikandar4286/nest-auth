import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { Injectable } from '@nestjs/common';

@Injectable()
export class MailService {
  private transporter: nodemailer.Transporter;

  constructor(private readonly configService: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: this.configService.get('mailtrap.host'),
      port: this.configService.get('mailtrap.port'),
      auth: {
        user: this.configService.get('mailtrap.user'),
        pass: this.configService.get('mailtrap.pass'),
      },
    });
  }

  async sendResetPasswordEmail(email: string, token: string) {
    const resetPasswordUrl = `${this.configService.get('frontend.url')}/reset-password?token=${token}`;
    const mail = {
      from: this.configService.get('mailtrap.from'),
      to: email,
      subject: 'Reset Password',
      text: `Click the link to reset your password: ${resetPasswordUrl}`,
    };

    await this.transporter.sendMail(mail);
  }
}
