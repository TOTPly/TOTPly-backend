import { Injectable } from '@nestjs/common';
import { Resend } from 'resend';

@Injectable()
export class EmailService {
  private resend: Resend;

  constructor() {
    this.resend = new Resend(process.env.RESEND_API_KEY);
  }

  async sendVerificationEmail(email: string, code: string) {
    try {
      await this.resend.emails.send({
        from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
        to: email,
        subject: 'Verify your email - TOTPly',
        html: `
          <h1>Email Verification</h1>
          <p>Your verification code is: <strong>${code}</strong></p>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      });
    } catch (error) {
      console.error('Failed to send email:', error);
      throw new Error('Failed to send verification email');
    }
  }

  async sendLoginCode(email: string, code: string) {
    try {
      await this.resend.emails.send({
        from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
        to: email,
        subject: 'Your login code - TOTPly',
        html: `
          <h1>Login Verification</h1>
          <p>Your login code is: <strong>${code}</strong></p>
          <p>This code will expire in 15 minutes.</p>
          <p>If you didn't request this, please secure your account immediately.</p>
        `,
      });
    } catch (error) {
      console.error('Failed to send email:', error);
      throw new Error('Failed to send login code email');
    }
  }

  async sendPasswordResetEmail(email: string, token: string) {
    try {
      await this.resend.emails.send({
        from: process.env.EMAIL_FROM || 'onboarding@resend.dev',
        to: email,
        subject: 'Reset your password - TOTPly',
        html: `
          <h1>Password Reset</h1>
          <p>Click the link below to reset your password:</p>
          <p><a href="${process.env.FRONTEND_URL}/reset-password?token=${token}">Reset Password</a></p>
          <p>This link will expire in 1 hour.</p>
          <p>If you didn't request this, please ignore this email.</p>
        `,
      });
    } catch (error) {
      console.error('Failed to send email:', error);
      throw new Error('Failed to send password reset email');
    }
  }
}
