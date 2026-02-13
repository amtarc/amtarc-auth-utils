/**
 * Fixed Window Algorithm
 *
 * Simple counter that resets at fixed intervals.
 * Can allow bursts at window boundaries (double the limit).
 */

import type { RateLimitOptions, RateLimitResult } from '../types';

export async function fixedWindow(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const { max, window, storage } = options;

  if (!storage) {
    throw new Error('Storage adapter required for fixed window');
  }

  const now = Date.now();
  const windowStart = Math.floor(now / window) * window;
  const windowKey = `window:${key}:${windowStart}`;

  // Get current count
  const countValue = await storage.get(windowKey);
  let count = typeof countValue === 'number' ? countValue : 0;

  // Check if allowed
  const allowed = count < max;

  if (allowed) {
    count = await storage.increment(windowKey, 1);
    // Set TTL to window duration
    await storage.set(windowKey, count, window);
  }

  const resetAt = windowStart + window;

  const result: RateLimitResult = {
    allowed,
    limit: max,
    remaining: Math.max(0, max - count),
    resetAt,
  };

  if (!allowed) {
    result.retryAfter = Math.ceil((resetAt - now) / 1000);
  }

  return result;
}
