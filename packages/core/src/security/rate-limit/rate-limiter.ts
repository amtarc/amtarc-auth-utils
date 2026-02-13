/**
 * Main rate limiter factory
 */

import type { RateLimitOptions, RateLimitResult } from './types';
import { tokenBucket } from './algorithms/token-bucket';
import { fixedWindow } from './algorithms/fixed-window';
import { slidingWindowLog } from './algorithms/sliding-window-log';
import { slidingWindowCounter } from './algorithms/sliding-window-counter';
import { MemoryRateLimitStorage } from './storage/memory-storage';

export function createRateLimiter(options: RateLimitOptions) {
  const {
    algorithm = 'sliding-window-counter',
    storage = new MemoryRateLimitStorage(),
    keyPrefix = 'ratelimit',
  } = options;

  const algorithmMap = {
    'token-bucket': tokenBucket,
    'fixed-window': fixedWindow,
    'sliding-window-log': slidingWindowLog,
    'sliding-window-counter': slidingWindowCounter,
  };

  const algorithmFn = algorithmMap[algorithm];

  if (!algorithmFn) {
    throw new Error(`Unknown algorithm: ${algorithm}`);
  }

  return async (key: string): Promise<RateLimitResult> => {
    const prefixedKey = `${keyPrefix}:${key}`;
    return algorithmFn(prefixedKey, { ...options, storage });
  };
}

/**
 * Convenience function to check rate limit
 */
export async function checkRateLimit(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const limiter = createRateLimiter(options);
  return limiter(key);
}
