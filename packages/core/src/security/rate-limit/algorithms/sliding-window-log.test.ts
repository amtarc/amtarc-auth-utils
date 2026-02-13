/**
 * Sliding Window Log Algorithm Tests
 */

import { describe, it, expect } from 'vitest';
import { createRateLimiter } from '../rate-limiter';

describe('Sliding Window Log Algorithm', () => {
  it('should track request timestamps', async () => {
    const limiter = createRateLimiter({
      max: 3,
      window: 1000,
      algorithm: 'sliding-window-log',
    });

    const results = [];
    for (let i = 0; i < 3; i++) {
      results.push(await limiter('user-1'));
    }

    expect(results.every((r) => r.allowed)).toBe(true);

    const blocked = await limiter('user-1');
    expect(blocked.allowed).toBe(false);
  });

  it('should remove old timestamps', async () => {
    const limiter = createRateLimiter({
      max: 2,
      window: 100,
      algorithm: 'sliding-window-log',
    });

    await limiter('user-1');
    await new Promise((resolve) => setTimeout(resolve, 60));
    await limiter('user-1');

    // Both requests should be in the log
    let result = await limiter('user-1');
    expect(result.allowed).toBe(false);

    // Wait for first request to expire
    await new Promise((resolve) => setTimeout(resolve, 60));

    result = await limiter('user-1');
    expect(result.allowed).toBe(true);
  }, 10000);
});
