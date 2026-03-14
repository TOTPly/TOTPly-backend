import { Controller, Get, Post, Patch, Delete, Body, Param, Req, UseGuards } from '@nestjs/common';
import { TotpService } from './totp.service';
import { CreateTotpDto } from './dto/create-totp.dto';
import { UpdateTotpDto } from './dto/update-totp.dto';
import { JwtGuard } from '../auth/jwt.guard';
import { Throttle } from '@nestjs/throttler';
import type { Request } from 'express';

@Controller('totp')
@UseGuards(JwtGuard)
export class TotpController {
  constructor(private totpService: TotpService) {}

  @Post()
  async create(@Req() req: Request, @Body() dto: CreateTotpDto) {
    const user = req['user'] as any;
    return this.totpService.create(user.sub, dto);
  }

  @Get()
  async findAll(@Req() req: Request) {
    const user = req['user'] as any;
    return this.totpService.findAll(user.sub);
  }

  @Get(':id')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async findOne(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    return this.totpService.findOne(user.sub, id);
  }

  @Patch(':id')
  async update(@Req() req: Request, @Param('id') id: string, @Body() dto: UpdateTotpDto) {
    const user = req['user'] as any;
    return this.totpService.update(user.sub, id, dto);
  }

  @Delete(':id')
  async remove(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    return this.totpService.remove(user.sub, id);
  }
}
