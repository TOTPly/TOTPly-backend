import {
  Injectable, NestInterceptor, ExecutionContext, CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { createHash } from 'crypto';
import type { Request, Response } from 'express';

export const SKIP_ETAG_KEY = 'skip-etag';

@Injectable()
export class EtagInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType<string>() === 'graphql') {
      return next.handle();
    }

    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();

    if (req.method !== 'GET') {
      return next.handle();
    }

    const skip = this.reflector.getAllAndOverride<boolean>(SKIP_ETAG_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (skip) {
      return next.handle();
    }

    return next.handle().pipe(
      map((body) => {
        if (body === undefined || body === null) return body;

        const data = Buffer.isBuffer(body) ? body : JSON.stringify(body);
        const hash = createHash('md5').update(data).digest('hex');
        const etag = `"${hash}"`;

        res.setHeader('ETag', etag);

        const ifNoneMatch = req.headers['if-none-match'];
        if (ifNoneMatch === etag) {
          res.status(304);
          return null;
        }

        return body;
      }),
    );
  }
}
