/**
 * Token Bucket Algorithm
 *
 * Allows bursts while maintaining average rate.
 * Tokens are added at a constant rate, requests consume tokens.
 */

import type { RateLimitOptions, RateLimitResult } from '../types';

export interface TokenBucketState {
  tokens: number;
  lastRefill: number;
}

export async function tokenBucket(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult> {
  const { max, window, storage } = options;

  if (!storage) {
    throw new Error('Storage adapter required for token bucket');
  }

  const now = Date.now();
  const refillRate = max / window; // tokens per ms
  const bucketKey = `bucket:${key}`;

  // Get current state
  const stateValue = await storage.get(bucketKey);
  let state: TokenBucketState;

  if (!stateValue || typeof stateValue !== 'object') {
    // Initialize bucket
    state = {
      tokens: max,
      lastRefill: now,
    };
  } else {
    const existingState = stateValue as TokenBucketState;
    // Refill tokens based on time elapsed
    const elapsed = now - existingState.lastRefill;
    const tokensToAdd = elapsed * refillRate;
    state = {
      tokens: Math.min(max, existingState.tokens + tokensToAdd),
      lastRefill: now,
    };
  }

  // Check if request allowed
  const allowed = state.tokens >= 1;

  if (allowed) {
    state.tokens -= 1;
  }

  // Save state
  await storage.set(bucketKey, state, window);

  // Calculate reset time
  const tokensNeeded = allowed ? 0 : 1 - state.tokens;
  const msUntilToken = tokensNeeded / refillRate;
  const resetAt = now + msUntilToken;

  const result: RateLimitResult = {
    allowed,
    limit: max,
    remaining: Math.floor(state.tokens),
    resetAt,
  };

  if (!allowed) {
    result.retryAfter = Math.ceil(msUntilToken / 1000);
  }

  return result;
}
