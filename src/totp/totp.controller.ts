import { Controller, Get, Post, Patch, Delete, Body, Param, Req, Res, Sse, UseGuards, MessageEvent } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth, ApiParam } from '@nestjs/swagger';
import { TotpService } from './totp.service';
import { TotpCacheService } from './totp-cache.service';
import { CreateTotpDto } from './dto/create-totp.dto';
import { UpdateTotpDto } from './dto/update-totp.dto';
import { ImportUriDto } from './dto/import-uri.dto';
import { ImportBatchDto } from './dto/import-batch.dto';
import { JwtGuard } from '../auth/jwt.guard';
import { CacheControl } from '../common/decorators/cache-control.decorator';
import { SkipEtag } from '../common/decorators/skip-etag.decorator';
import { Throttle } from '@nestjs/throttler';
import type { Request, Response } from 'express';
import * as QRCode from 'qrcode';
import { Observable, interval, switchMap, map } from 'rxjs';

@ApiTags('TOTP')
@ApiBearerAuth()
@Controller('totp')
@UseGuards(JwtGuard)
export class TotpController {
  constructor(
    private totpService: TotpService,
    private totpCacheService: TotpCacheService,
  ) {}

  @Post()
  @ApiOperation({ summary: 'Create a new TOTP entry' })
  @ApiResponse({ status: 201, description: 'TOTP entry created' })
  @ApiResponse({ status: 400, description: 'Invalid input' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async create(@Req() req: Request, @Body() dto: CreateTotpDto) {
    const user = req['user'] as any;
    const result = await this.totpService.create(user.sub, dto);
    await this.totpCacheService.invalidateForUser(user.sub);
    return result;
  }

  @Get()
  @CacheControl('private, max-age=5')
  @ApiOperation({ summary: 'Get all TOTP entries' })
  @ApiResponse({ status: 200, description: 'List of TOTP entries' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async findAll(@Req() req: Request) {
    const user = req['user'] as any;
    const cacheKey = this.totpCacheService.listKey(user.sub);
    const cached = await this.totpCacheService.get(cacheKey);
    if (cached) return cached;

    const result = await this.totpService.findAll(user.sub);
    await this.totpCacheService.set(cacheKey, result, 5000);
    return result;
  }

  @Get('codes')
  @SkipEtag()
  @ApiOperation({ summary: 'Get current codes for all TOTP entries' })
  @ApiResponse({ status: 200, description: 'List of current TOTP codes' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  async getAllCodes(@Req() req: Request) {
    const user = req['user'] as any;
    return this.totpService.generateAllCodes(user.sub);
  }

  @Sse('codes/stream')
  @SkipEtag()
  @ApiOperation({ summary: 'SSE stream of TOTP codes (updates every 2s)' })
  @ApiResponse({ status: 200, description: 'SSE event stream' })
  codesStream(@Req() req: Request): Observable<MessageEvent> {
    const user = req['user'] as any;
    return interval(2000).pipe(
      switchMap(() => this.totpService.generateAllCodes(user.sub)),
      map((codes) => ({ data: codes }) as MessageEvent),
    );
  }

  @Get(':id')
  @CacheControl('private, max-age=10')
  @ApiOperation({ summary: 'Get a single TOTP entry' })
  @ApiParam({ name: 'id', description: 'TOTP entry ID' })
  @ApiResponse({ status: 200, description: 'TOTP entry details' })
  @ApiResponse({ status: 404, description: 'Entry not found' })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async findOne(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    const cacheKey = this.totpCacheService.detailKey(user.sub, id);
    const cached = await this.totpCacheService.get(cacheKey);
    if (cached) return cached;

    const result = await this.totpService.findOne(user.sub, id);
    await this.totpCacheService.set(cacheKey, result, 10000);
    return result;
  }

  @Get(':id/code')
  @SkipEtag()
  @ApiOperation({ summary: 'Generate current TOTP code' })
  @ApiParam({ name: 'id', description: 'TOTP entry ID' })
  @ApiResponse({ status: 200, description: 'Current TOTP code with remaining seconds' })
  @ApiResponse({ status: 404, description: 'Entry not found' })
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  async getCode(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    return this.totpService.generateCode(user.sub, id);
  }

  @Get(':id/uri')
  @CacheControl('private, max-age=30')
  @ApiOperation({ summary: 'Get otpauth:// URI for entry' })
  @ApiParam({ name: 'id', description: 'TOTP entry ID' })
  @ApiResponse({ status: 200, description: 'otpauth URI' })
  @ApiResponse({ status: 404, description: 'Entry not found' })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async getUri(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    const cacheKey = this.totpCacheService.uriKey(user.sub, id);
    const cached = await this.totpCacheService.get(cacheKey);
    if (cached) return cached;

    const result = await this.totpService.getUri(user.sub, id);
    await this.totpCacheService.set(cacheKey, result, 30000);
    return result;
  }

  @Get(':id/qr')
  @CacheControl('private, max-age=60')
  @ApiOperation({ summary: 'Get QR code image for entry' })
  @ApiParam({ name: 'id', description: 'TOTP entry ID' })
  @ApiResponse({ status: 200, description: 'QR code PNG image' })
  @ApiResponse({ status: 404, description: 'Entry not found' })
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  async getQr(@Req() req: Request, @Res({ passthrough: true }) res: Response, @Param('id') id: string) {
    const user = req['user'] as any;
    const cacheKey = this.totpCacheService.qrKey(user.sub, id);

    let qrBuffer = await this.totpCacheService.get<Buffer>(cacheKey);
    if (!qrBuffer) {
      const { uri } = await this.totpService.getUri(user.sub, id);
      qrBuffer = await QRCode.toBuffer(uri, { type: 'png', width: 256 });
      await this.totpCacheService.set(cacheKey, qrBuffer, 60000);
    }

    res.set('Content-Type', 'image/png');
    return qrBuffer;
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a TOTP entry' })
  @ApiParam({ name: 'id', description: 'TOTP entry ID' })
  @ApiResponse({ status: 200, description: 'Entry updated' })
  @ApiResponse({ status: 404, description: 'Entry not found' })
  async update(@Req() req: Request, @Param('id') id: string, @Body() dto: UpdateTotpDto) {
    const user = req['user'] as any;
    const result = await this.totpService.update(user.sub, id, dto);
    await this.totpCacheService.invalidateForUser(user.sub, id);
    return result;
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Delete a TOTP entry' })
  @ApiParam({ name: 'id', description: 'TOTP entry ID' })
  @ApiResponse({ status: 200, description: 'Entry deleted' })
  @ApiResponse({ status: 404, description: 'Entry not found' })
  async remove(@Req() req: Request, @Param('id') id: string) {
    const user = req['user'] as any;
    const result = await this.totpService.remove(user.sub, id);
    await this.totpCacheService.invalidateForUser(user.sub, id);
    return result;
  }

  @Post('import/uri')
  @ApiOperation({ summary: 'Import TOTP entry from otpauth URI' })
  @ApiResponse({ status: 201, description: 'Entry imported' })
  @ApiResponse({ status: 400, description: 'Invalid URI' })
  async importUri(@Req() req: Request, @Body() dto: ImportUriDto) {
    const user = req['user'] as any;
    const result = await this.totpService.importFromUri(user.sub, dto.uri);
    await this.totpCacheService.invalidateForUser(user.sub);
    return result;
  }

  @Post('import/batch')
  @ApiOperation({ summary: 'Import multiple TOTP entries from URIs' })
  @ApiResponse({ status: 201, description: 'Entries imported' })
  @ApiResponse({ status: 400, description: 'Invalid URIs' })
  async importBatch(@Req() req: Request, @Body() dto: ImportBatchDto) {
    const user = req['user'] as any;
    const result = await this.totpService.importBatch(user.sub, dto.uris);
    await this.totpCacheService.invalidateForUser(user.sub);
    return result;
  }
}
