import {
  Injectable, NestInterceptor, ExecutionContext, CallHandler, Logger,
} from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import type { Response } from 'express';

@Injectable()
export class TimingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(TimingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const start = Date.now();

    let res: Response | null = null;
    if (context.getType<string>() === 'graphql') {
      const gqlCtx = GqlExecutionContext.create(context);
      res = gqlCtx.getContext().req?.res;
    } else {
      res = context.switchToHttp().getResponse();
    }

    return next.handle().pipe(
      tap(() => {
        const elapsed = Date.now() - start;
        this.logger.log(`${context.getClass().name}.${context.getHandler().name} — ${elapsed}ms`);
        if (res && typeof res.setHeader === 'function' && !res.headersSent) {
          res.setHeader('X-Elapsed-Time', `${elapsed}ms`);
        }
      }),
    );
  }
}
