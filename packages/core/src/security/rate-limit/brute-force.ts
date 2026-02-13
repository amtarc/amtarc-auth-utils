/**
 * Brute-force attack protection
 * Progressive delays and account lockout
 */

import type { RateLimitStorage } from './types';
import { MemoryRateLimitStorage } from './storage/memory-storage';

export interface BruteForceOptions {
  /** Max failed attempts before lockout */
  maxAttempts: number;
  /** Lockout duration in ms */
  lockoutDuration: number;
  /** Progressive delay multiplier */
  delayMultiplier?: number;
  /** Base delay in ms */
  baseDelay?: number;
  /** Storage adapter */
  storage?: RateLimitStorage;
}

export interface BruteForceResult {
  allowed: boolean;
  attemptsRemaining: number;
  lockedUntil?: number;
  retryAfter?: number;
}

export class BruteForceProtection {
  private storage: RateLimitStorage;
  private options: Required<BruteForceOptions>;

  constructor(options: BruteForceOptions) {
    this.storage = options.storage || new MemoryRateLimitStorage();
    this.options = {
      delayMultiplier: 2,
      baseDelay: 1000,
      storage: this.storage,
      ...options,
    };
  }

  async checkAttempt(key: string): Promise<BruteForceResult> {
    const attemptsKey = `bruteforce:attempts:${key}`;
    const lockKey = `bruteforce:lock:${key}`;

    // Check if locked
    const lockedUntilValue = await this.storage.get(lockKey);
    const lockedUntil =
      typeof lockedUntilValue === 'number' ? lockedUntilValue : 0;
    if (lockedUntil && Date.now() < lockedUntil) {
      return {
        allowed: false,
        attemptsRemaining: 0,
        lockedUntil,
        retryAfter: Math.ceil((lockedUntil - Date.now()) / 1000),
      };
    }

    // Get attempt count
    const attemptsValue = await this.storage.get(attemptsKey);
    const attempts = typeof attemptsValue === 'number' ? attemptsValue : 0;
    const attemptsRemaining = Math.max(0, this.options.maxAttempts - attempts);

    return {
      allowed: true,
      attemptsRemaining,
    };
  }

  async recordFailedAttempt(key: string): Promise<BruteForceResult> {
    const attemptsKey = `bruteforce:attempts:${key}`;
    const lockKey = `bruteforce:lock:${key}`;

    // Increment attempts
    const attempts = await this.storage.increment(attemptsKey, 1);
    await this.storage.set(attemptsKey, attempts, this.options.lockoutDuration);

    // Check if should lock
    if (attempts >= this.options.maxAttempts) {
      const lockedUntil = Date.now() + this.options.lockoutDuration;
      await this.storage.set(
        lockKey,
        lockedUntil,
        this.options.lockoutDuration
      );

      return {
        allowed: false,
        attemptsRemaining: 0,
        lockedUntil,
        retryAfter: Math.ceil(this.options.lockoutDuration / 1000),
      };
    }

    // Calculate progressive delay
    const delay =
      this.options.baseDelay *
      Math.pow(this.options.delayMultiplier, attempts - 1);

    return {
      allowed: true,
      attemptsRemaining: this.options.maxAttempts - attempts,
      retryAfter: Math.ceil(delay / 1000),
    };
  }

  async recordSuccessfulAttempt(key: string): Promise<void> {
    const attemptsKey = `bruteforce:attempts:${key}`;
    const lockKey = `bruteforce:lock:${key}`;

    await this.storage.delete(attemptsKey);
    await this.storage.delete(lockKey);
  }

  async unlock(key: string): Promise<void> {
    await this.recordSuccessfulAttempt(key);
  }
}
