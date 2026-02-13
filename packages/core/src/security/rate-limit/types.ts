/**
 * Rate limiting type definitions
 */

export interface RateLimitOptions {
  /** Maximum number of requests */
  max: number;
  /** Time window in milliseconds */
  window: number;
  /** Algorithm to use */
  algorithm?:
    | 'token-bucket'
    | 'fixed-window'
    | 'sliding-window-log'
    | 'sliding-window-counter';
  /** Storage adapter */
  storage?: RateLimitStorage;
  /** Key prefix for storage */
  keyPrefix?: string;
}

export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Total limit */
  limit: number;
  /** Remaining requests */
  remaining: number;
  /** Reset time (timestamp) */
  resetAt: number;
  /** Retry after (seconds) if not allowed */
  retryAfter?: number;
}

export interface RateLimitInfo {
  /** Current count */
  current: number;
  /** Total limit */
  limit: number;
  /** Window start timestamp */
  windowStart: number;
  /** Window end timestamp */
  windowEnd: number;
}

import type { CounterStorage } from '../../storage/base-storage';

/**
 * Rate limit storage interface
 * Extends CounterStorage for compatibility with other modules
 */
export interface RateLimitStorage extends CounterStorage {}
