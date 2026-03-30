import {
  Injectable, NestInterceptor, ExecutionContext, CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { CACHE_CONTROL_KEY } from '../decorators/cache-control.decorator';
import type { Response } from 'express';

@Injectable()
export class CacheControlInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType<string>() === 'graphql') {
      return next.handle();
    }

    const value = this.reflector.getAllAndOverride<string>(CACHE_CONTROL_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (value) {
      const res = context.switchToHttp().getResponse<Response>();
      res.setHeader('Cache-Control', value);
    }

    return next.handle();
  }
}
