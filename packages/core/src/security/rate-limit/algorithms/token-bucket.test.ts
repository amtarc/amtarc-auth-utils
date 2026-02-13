/**
 * Token Bucket Algorithm Tests
 */

import { describe, it, expect } from 'vitest';
import { createRateLimiter } from '../rate-limiter';

describe('Token Bucket Algorithm', () => {
  it('should allow requests within limit', async () => {
    const limiter = createRateLimiter({
      max: 5,
      window: 60000,
      algorithm: 'token-bucket',
    });

    for (let i = 0; i < 5; i++) {
      const result = await limiter('user-1');
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBeGreaterThanOrEqual(0);
    }
  });

  it('should block requests exceeding limit', async () => {
    const limiter = createRateLimiter({
      max: 3,
      window: 60000,
      algorithm: 'token-bucket',
    });

    // Use up all tokens
    for (let i = 0; i < 3; i++) {
      await limiter('user-1');
    }

    // Next request should be blocked
    const result = await limiter('user-1');
    expect(result.allowed).toBe(false);
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('should refill tokens over time', async () => {
    const limiter = createRateLimiter({
      max: 2,
      window: 100, // 100ms window
      algorithm: 'token-bucket',
    });

    // Use all tokens
    await limiter('user-1');
    await limiter('user-1');

    // Should be blocked immediately
    let result = await limiter('user-1');
    expect(result.allowed).toBe(false);

    // Wait for token refill
    await new Promise((resolve) => setTimeout(resolve, 60));

    // Should allow now
    result = await limiter('user-1');
    expect(result.allowed).toBe(true);
  }, 10000);
});
