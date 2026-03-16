import { Controller, Get, Post, Patch, Delete, Body, Param, Req, Res, UseGuards } from '@nestjs/common';
import { TotpService } from './totp.service';
import { CreateTotpDto } from './dto/create-totp.dto';
import { UpdateTotpDto } from './dto/update-totp.dto';
import { ImportUriDto } from './dto/import-uri.dto';
import { ImportBatchDto } from './dto/import-batch.dto';
import { JwtGuard } from '../auth/jwt.guard';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import * as QRCode from 'qrcode';

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

  @Get('codes')
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  async getAllCodes(@Req() req: Request) {
    const user = req['user'] as any;
    return this.totpService.generateAllCodes(user.sub);
  }

  @Get(':id')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async findOne(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    return this.totpService.findOne(user.sub, id);
  }

  @Get(':id/code')
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  async getCode(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    return this.totpService.generateCode(user.sub, id);
  }

  @Get(':id/uri')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async getUri(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    return this.totpService.getUri(user.sub, id);
  }

  @Get(':id/qr')
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async getQr(@Req() req: Request, @Res() res: Response, @Param('id') id: string) {
    const user = req['user'] as any;
    const { uri } = await this.totpService.getUri(user.sub, id);
    const qrBuffer = await QRCode.toBuffer(uri, { type: 'png', width: 256 });
    res.set({ 'Content-Type': 'image/png', 'Cache-Control': 'no-store' });
    res.send(qrBuffer);
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

  @Post('import/uri')
  async importUri(@Req() req: Request, @Body() dto: ImportUriDto) {
    const user = req['user'] as any;
    return this.totpService.importFromUri(user.sub, dto.uri);
  }

  @Post('import/batch')
  async importBatch(@Req() req: Request, @Body() dto: ImportBatchDto) {
    const user = req['user'] as any;
    return this.totpService.importBatch(user.sub, dto.uris);
  }
}
