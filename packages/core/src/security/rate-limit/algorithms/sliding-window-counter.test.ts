/**
 * Sliding Window Counter Algorithm Tests
 */

import { describe, it, expect } from 'vitest';
import { createRateLimiter } from '../rate-limiter';

describe('Sliding Window Counter Algorithm', () => {
  it('should use weighted counting', async () => {
    const limiter = createRateLimiter({
      max: 5,
      window: 60000,
      algorithm: 'sliding-window-counter',
    });

    for (let i = 0; i < 5; i++) {
      const result = await limiter('user-1');
      expect(result.allowed).toBe(true);
    }

    const result = await limiter('user-1');
    expect(result.allowed).toBe(false);
  });

  it('should provide smooth rate limiting', async () => {
    const limiter = createRateLimiter({
      max: 3,
      window: 1000,
      algorithm: 'sliding-window-counter',
    });

    // Make requests across window boundary
    await limiter('user-1');
    await limiter('user-1');

    await new Promise((resolve) => setTimeout(resolve, 600));

    const result = await limiter('user-1');
    expect(result.allowed).toBe(true);
  }, 10000);
});
