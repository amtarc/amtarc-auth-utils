/**
 * Sliding Window Counter Algorithm
 *
 * Hybrid approach: combines fixed windows with weighted counting.
 * Good balance between accuracy and performance.
 */

import type { RateLimitOptions, RateLimitResult } from '../types';

export async function slidingWindowCounter(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const { max, window, storage } = options;

  if (!storage) {
    throw new Error('Storage adapter required for sliding window counter');
  }

  const now = Date.now();

  // Calculate current and previous windows
  const currentWindowStart = Math.floor(now / window) * window;
  const previousWindowStart = currentWindowStart - window;

  const currentWindowKey = `counter:${key}:${currentWindowStart}`;
  const previousWindowKey = `counter:${key}:${previousWindowStart}`;

  // Get counts
  const currentCountValue = await storage.get(currentWindowKey);
  const previousCountValue = await storage.get(previousWindowKey);
  const currentCount =
    typeof currentCountValue === 'number' ? currentCountValue : 0;
  const previousCount =
    typeof previousCountValue === 'number' ? previousCountValue : 0;

  // Calculate weighted count
  const percentage = (now - currentWindowStart) / window;
  const weightedCount = previousCount * (1 - percentage) + currentCount;

  // Check if allowed
  const allowed = weightedCount < max;

  if (allowed) {
    const newCount = await storage.increment(currentWindowKey, 1);
    await storage.set(currentWindowKey, newCount, window * 2);
  }

  const remaining = Math.max(0, Math.floor(max - weightedCount));
  const resetAt = currentWindowStart + window;

  const result: RateLimitResult = {
    allowed,
    limit: max,
    remaining,
    resetAt,
  };

  if (!allowed) {
    result.retryAfter = Math.ceil((resetAt - now) / 1000);
  }

  return result;
}
