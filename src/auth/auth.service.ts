import { Injectable, UnauthorizedException, ConflictException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { EmailService } from '../email/email.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private emailService: EmailService,
  ) {}

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }

  async register(email: string, password: string) {
    const hashed = await bcrypt.hash(password, 10);

    try {
      const verificationCode = this.generateVerificationCode();
      const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

      await this.prisma.user.create({
        data: {
          email,
          passwordHash: hashed,
          emailVerifyCode: verificationCode,
          emailVerifyExpires: verificationExpires,
        },
      });

      await this.emailService.sendVerificationEmail(email, verificationCode);

      return { message: 'Registration successful. Please check your email for verification code.' };
    } catch (error: any) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email already registered');
      }
      throw error;
    }
  }

  async login(email: string, password: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) throw new UnauthorizedException('Invalid credentials');

    const loginCode = this.generateVerificationCode();
    const loginCodeExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        loginCode,
        loginCodeExpires,
      },
    });

    await this.emailService.sendLoginCode(email, loginCode);

    // Создаем временный токен для верификации
    const tempToken = this.jwtService.sign(
      { email, purpose: 'login-verification' },
      { expiresIn: '10m' },
    );

    return { requireEmailCode: true, tempToken };
  }

  async verifyLogin(tempToken: string, code: string, userAgent?: string) {
    let email: string;
    
    try {
      const payload: any = this.jwtService.verify(tempToken, { secret: process.env.JWT_SECRET });
      if (payload.purpose !== 'login-verification') {
        throw new UnauthorizedException('Invalid token');
      }
      email = payload.email;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }

    const user = await this.prisma.user.findUnique({ where: { email } });
    
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    if (!user.loginCode || !user.loginCodeExpires) {
      throw new BadRequestException('No login code found. Please login first.');
    }

    if (user.loginCodeExpires < new Date()) {
      throw new BadRequestException('Login code expired. Please login again.');
    }

    if (user.loginCode !== code) {
      throw new BadRequestException('Invalid login code');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        loginCode: null,
        loginCodeExpires: null,
      },
    });

    const sessionId = uuidv4();
    const tokenId = uuidv4();
    const expiresAt = new Date(Date.now() + Number(process.env.JWT_EXPIRES) * 1000);

    await this.prisma.session.create({
      data: {
        id: sessionId,
        userId: user.id,
        tokenId,
        expiresAt,
        userAgent,
      },
    });

    const token = this.jwtService.sign(
      { sub: user.id, email: user.email, sessionId },
      { expiresIn: Number(process.env.JWT_EXPIRES), jwtid: tokenId },
    );

    return { token };
  }

  async verifyEmail(email: string, code: string, userAgent?: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email already verified');
    }

    if (!user.emailVerifyCode || !user.emailVerifyExpires) {
      throw new BadRequestException('No verification code found');
    }

    if (user.emailVerifyExpires < new Date()) {
      throw new BadRequestException('Verification code expired');
    }

    if (user.emailVerifyCode !== code) {
      throw new BadRequestException('Invalid verification code');
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerified: true,
        emailVerifyCode: null,
        emailVerifyExpires: null,
      },
    });

    const sessionId = uuidv4();
    const tokenId = uuidv4();
    const expiresAt = new Date(Date.now() + Number(process.env.JWT_EXPIRES) * 1000);

    await this.prisma.session.create({
      data: {
        id: sessionId,
        userId: user.id,
        tokenId,
        expiresAt,
        userAgent,
      },
    });

    const token = this.jwtService.sign(
      { sub: user.id, email: user.email, sessionId },
      { expiresIn: Number(process.env.JWT_EXPIRES), jwtid: tokenId },
    );

    return { token };
  }

  async resendVerification(email: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email already verified');
    }

    const verificationCode = this.generateVerificationCode();
    const verificationExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        emailVerifyCode: verificationCode,
        emailVerifyExpires: verificationExpires,
      },
    });

    await this.emailService.sendVerificationEmail(email, verificationCode);

    return { message: 'Verification code sent successfully' };
  }
}