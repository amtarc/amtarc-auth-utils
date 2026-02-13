/**
 * Fixed Window Algorithm Tests
 */

import { describe, it, expect } from 'vitest';
import { createRateLimiter } from '../rate-limiter';

describe('Fixed Window Algorithm', () => {
  it('should allow requests within window', async () => {
    const limiter = createRateLimiter({
      max: 5,
      window: 60000,
      algorithm: 'fixed-window',
    });

    for (let i = 0; i < 5; i++) {
      const result = await limiter('user-1');
      expect(result.allowed).toBe(true);
    }
  });

  it('should block requests exceeding window limit', async () => {
    const limiter = createRateLimiter({
      max: 3,
      window: 60000,
      algorithm: 'fixed-window',
    });

    for (let i = 0; i < 3; i++) {
      await limiter('user-1');
    }

    const result = await limiter('user-1');
    expect(result.allowed).toBe(false);
  });

  it('should reset count in new window', async () => {
    const limiter = createRateLimiter({
      max: 2,
      window: 100,
      algorithm: 'fixed-window',
    });

    await limiter('user-1');
    await limiter('user-1');

    // Should be blocked
    let result = await limiter('user-1');
    expect(result.allowed).toBe(false);

    // Wait for new window
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Should allow in new window
    result = await limiter('user-1');
    expect(result.allowed).toBe(true);
  }, 10000);
});
