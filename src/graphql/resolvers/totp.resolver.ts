import {
  Resolver, Query, Mutation, Args, Context,
  ResolveField, Parent,
} from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { JwtGuard } from '../../auth/jwt.guard';
import { TotpService } from '../../totp/totp.service';
import { TotpCacheService } from '../../totp/totp-cache.service';
import { TotpEntry } from '../types/totp-entry.type';
import { TotpEntryDetail } from '../types/totp-entry-detail.type';
import { TotpCode } from '../types/totp-code.type';
import { TotpCodeWithEntry } from '../types/totp-code-with-entry.type';
import { TotpUriResponse } from '../types/totp-uri.type';
import { MessageResponse } from '../types/message.type';
import { PaginatedTotpEntries } from '../types/paginated-totp-entries.type';
import { CreateTotpInput } from '../inputs/create-totp.input';
import { UpdateTotpInput } from '../inputs/update-totp.input';
import { ImportUriInput } from '../inputs/import-uri.input';
import { ImportBatchInput } from '../inputs/import-batch.input';
import { PaginationInput } from '../inputs/pagination.input';

@Resolver(() => TotpEntry)
@UseGuards(JwtGuard)
export class TotpResolver {
  constructor(
    private totpService: TotpService,
    private totpCacheService: TotpCacheService,
  ) {}

  @Query(() => PaginatedTotpEntries, { name: 'totpEntries', description: 'Get paginated list of TOTP entries' })
  async getTotpEntries(
    @Context() ctx: any,
    @Args('pagination', { nullable: true }) pagination?: PaginationInput,
  ): Promise<PaginatedTotpEntries> {
    const userId = ctx.req.user.sub;
    const offset = pagination?.offset ?? 0;
    const limit = pagination?.limit ?? 20;

    const cacheKey = this.totpCacheService.listKey(userId);
    let allEntries = await this.totpCacheService.get<any[]>(cacheKey);
    if (!allEntries) {
      allEntries = await this.totpService.findAll(userId);
      await this.totpCacheService.set(cacheKey, allEntries, 5000);
    }

    const total = allEntries.length;
    const items = allEntries.slice(offset, offset + limit);

    return { items, total, offset, limit, hasMore: offset + limit < total };
  }

  @Query(() => TotpEntryDetail, { name: 'totpEntry', description: 'Get a single TOTP entry with decrypted secret' })
  async getTotpEntry(
    @Context() ctx: any,
    @Args('id') id: string,
  ): Promise<TotpEntryDetail> {
    const userId = ctx.req.user.sub;
    const cacheKey = this.totpCacheService.detailKey(userId, id);
    const cached = await this.totpCacheService.get<TotpEntryDetail>(cacheKey);
    if (cached) return cached;

    const result = await this.totpService.findOne(userId, id);
    await this.totpCacheService.set(cacheKey, result, 10000);
    return result;
  }

  @Query(() => TotpCode, { name: 'generateCode', description: 'Generate current TOTP code for an entry' })
  async getCode(
    @Context() ctx: any,
    @Args('id') id: string,
  ): Promise<TotpCode> {
    return this.totpService.generateCode(ctx.req.user.sub, id);
  }

  @Query(() => [TotpCodeWithEntry], { name: 'generateAllCodes', description: 'Generate current codes for all entries' })
  async getAllCodes(@Context() ctx: any): Promise<TotpCodeWithEntry[]> {
    return this.totpService.generateAllCodes(ctx.req.user.sub);
  }

  @Query(() => TotpUriResponse, { name: 'totpUri', description: 'Get otpauth:// URI for an entry' })
  async getUri(
    @Context() ctx: any,
    @Args('id') id: string,
  ): Promise<TotpUriResponse> {
    const userId = ctx.req.user.sub;
    const cacheKey = this.totpCacheService.uriKey(userId, id);
    const cached = await this.totpCacheService.get<TotpUriResponse>(cacheKey);
    if (cached) return cached;

    const result = await this.totpService.getUri(userId, id);
    await this.totpCacheService.set(cacheKey, result, 30000);
    return result;
  }

  @Mutation(() => TotpEntry, { description: 'Create a new TOTP entry' })
  async createTotp(
    @Context() ctx: any,
    @Args('input') input: CreateTotpInput,
  ): Promise<TotpEntry> {
    const userId = ctx.req.user.sub;
    const result = await this.totpService.create(userId, input);
    await this.totpCacheService.invalidateForUser(userId);
    return result;
  }

  @Mutation(() => TotpEntry, { description: 'Update TOTP entry metadata' })
  async updateTotp(
    @Context() ctx: any,
    @Args('id') id: string,
    @Args('input') input: UpdateTotpInput,
  ): Promise<TotpEntry> {
    const userId = ctx.req.user.sub;
    const result = await this.totpService.update(userId, id, input);
    await this.totpCacheService.invalidateForUser(userId, id);
    return result;
  }

  @Mutation(() => MessageResponse, { description: 'Delete a TOTP entry' })
  async removeTotp(
    @Context() ctx: any,
    @Args('id') id: string,
  ): Promise<MessageResponse> {
    const userId = ctx.req.user.sub;
    const result = await this.totpService.remove(userId, id);
    await this.totpCacheService.invalidateForUser(userId, id);
    return result;
  }

  @Mutation(() => TotpEntry, { description: 'Import TOTP entry from otpauth:// URI' })
  async importFromUri(
    @Context() ctx: any,
    @Args('input') input: ImportUriInput,
  ): Promise<TotpEntry> {
    const userId = ctx.req.user.sub;
    const result = await this.totpService.importFromUri(userId, input.uri);
    await this.totpCacheService.invalidateForUser(userId);
    return result;
  }

  @Mutation(() => [TotpEntry], { description: 'Import multiple TOTP entries from URIs' })
  async importBatch(
    @Context() ctx: any,
    @Args('input') input: ImportBatchInput,
  ): Promise<TotpEntry[]> {
    const userId = ctx.req.user.sub;
    const result = await this.totpService.importBatch(userId, input.uris);
    await this.totpCacheService.invalidateForUser(userId);
    return result;
  }

  @ResolveField(() => TotpCode, { name: 'currentCode', nullable: true, description: 'Current TOTP code for this entry' })
  async getCurrentCode(
    @Parent() entry: TotpEntry,
    @Context() ctx: any,
  ): Promise<TotpCode | null> {
    try {
      return await this.totpService.generateCode(ctx.req.user.sub, entry.id);
    } catch {
      return null;
    }
  }
}
