/**
 * Sliding Window Log Algorithm
 *
 * Maintains a log of all request timestamps.
 * Most accurate but memory-intensive.
 */

import type { RateLimitOptions, RateLimitResult } from '../types';

export async function slidingWindowLog(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const { max, window, storage } = options;

  if (!storage) {
    throw new Error('Storage adapter required for sliding window log');
  }

  const now = Date.now();
  const logKey = `log:${key}`;

  // Get request log
  const logValue = await storage.get(logKey);
  let log: number[] = Array.isArray(logValue) ? logValue : [];

  // Remove timestamps outside window
  const windowStart = now - window;
  log = log.filter((timestamp) => timestamp > windowStart);

  // Check if allowed
  const allowed = log.length < max;

  if (allowed) {
    log.push(now);
    await storage.set(logKey, log, window);
  }

  // Calculate reset time (when oldest request expires)
  const oldestTimestamp = log[0] || now;
  const resetAt = oldestTimestamp + window;

  const result: RateLimitResult = {
    allowed,
    limit: max,
    remaining: Math.max(0, max - log.length),
    resetAt,
  };

  if (!allowed) {
    result.retryAfter = Math.ceil((resetAt - now) / 1000);
  }

  return result;
}
