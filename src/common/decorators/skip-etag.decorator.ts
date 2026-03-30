import { SetMetadata } from '@nestjs/common';
import { SKIP_ETAG_KEY } from '../interceptors/etag.interceptor';

export const SkipEtag = () => SetMetadata(SKIP_ETAG_KEY, true);
