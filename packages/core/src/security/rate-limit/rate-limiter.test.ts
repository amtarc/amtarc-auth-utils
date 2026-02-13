/**
 * Rate Limiter Tests
 */

import { describe, it, expect } from 'vitest';
import { createRateLimiter, checkRateLimit } from './rate-limiter';

describe('createRateLimiter', () => {
  it('should create a rate limiter with default algorithm', async () => {
    const limiter = createRateLimiter({
      max: 5,
      window: 60000,
    });

    const result = await limiter('user-1');
    expect(result.allowed).toBe(true);
    expect(result.limit).toBe(5);
  });
});

describe('checkRateLimit', () => {
  it('should check rate limit', async () => {
    const result = await checkRateLimit('user-1', {
      max: 5,
      window: 60000,
    });

    expect(result.allowed).toBe(true);
    expect(result.limit).toBe(5);
    expect(result.remaining).toBeLessThanOrEqual(5);
  });
});
