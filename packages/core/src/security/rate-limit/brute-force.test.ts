/**
 * Brute Force Protection Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { BruteForceProtection } from './brute-force';

describe('BruteForceProtection', () => {
  let protection: BruteForceProtection;

  beforeEach(() => {
    protection = new BruteForceProtection({
      maxAttempts: 3,
      lockoutDuration: 60000,
      baseDelay: 1000,
    });
  });

  it('should allow attempts within limit', async () => {
    const result = await protection.checkAttempt('user-1');
    expect(result.allowed).toBe(true);
    expect(result.attemptsRemaining).toBe(3);
  });

  it('should track failed attempts', async () => {
    await protection.recordFailedAttempt('user-1');
    const result = await protection.checkAttempt('user-1');
    expect(result.attemptsRemaining).toBe(2);
  });

  it('should lockout after max attempts', async () => {
    for (let i = 0; i < 3; i++) {
      await protection.recordFailedAttempt('user-1');
    }

    const result = await protection.checkAttempt('user-1');
    expect(result.allowed).toBe(false);
    expect(result.lockedUntil).toBeDefined();
    expect(result.retryAfter).toBeGreaterThan(0);
  });

  it('should apply progressive delays', async () => {
    const result1 = await protection.recordFailedAttempt('user-1');
    expect(result1.retryAfter).toBe(1); // 1 second

    const result2 = await protection.recordFailedAttempt('user-1');
    expect(result2.retryAfter).toBe(2); // 2 seconds (baseDelay * 2^1)
  });

  it('should reset on successful attempt', async () => {
    await protection.recordFailedAttempt('user-1');
    await protection.recordSuccessfulAttempt('user-1');

    const result = await protection.checkAttempt('user-1');
    expect(result.attemptsRemaining).toBe(3);
  });

  it('should unlock manually', async () => {
    for (let i = 0; i < 3; i++) {
      await protection.recordFailedAttempt('user-1');
    }

    await protection.unlock('user-1');

    const result = await protection.checkAttempt('user-1');
    expect(result.allowed).toBe(true);
  });
});
