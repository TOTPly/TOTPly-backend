import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
  ) {}

  async register(email: string, password: string, userAgent?: string) {
    const hashed = await bcrypt.hash(password, 10);

    const user = await this.prisma.user.create({
      data: { email, passwordHash: hashed },
    });

    const sessionId = uuidv4();
    const expiresAt = new Date(Date.now() + Number(process.env.JWT_EXPIRES) * 1000);

    await this.prisma.session.create({
      data: {
        id: sessionId,
        userId: user.id,
        expiresAt,
        userAgent,
      },
    });

    const token = this.jwtService.sign(
      { sub: user.id, email: user.email, sessionId },
      { expiresIn: Number(process.env.JWT_EXPIRES) },
    );

    return { token };
  }

  async login(email: string, password: string, userAgent?: string) {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) throw new UnauthorizedException('Invalid credentials');

    if (!user.emailVerified) {
      throw new UnauthorizedException('Email not verified');
    }

    const sessionId = uuidv4();
    const expiresAt = new Date(Date.now() + Number(process.env.JWT_EXPIRES) * 1000);

    await this.prisma.session.create({
      data: {
        id: sessionId,
        userId: user.id,
        expiresAt,
        userAgent,
      },
    });

    const token = this.jwtService.sign(
      { sub: user.id, email: user.email, sessionId },
      { expiresIn: Number(process.env.JWT_EXPIRES) },
    );

    return { token };
  }
}