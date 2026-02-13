/**
 * Integration Tests
 * Tests showing how different modules work together
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { UniversalMemoryStorage } from '../../storage/universal-adapter';
import { createSession } from '../../session/create-session';
import {
  generateSynchronizerToken,
  validateSynchronizerToken,
  SessionCSRFAdapter,
} from './';
import { createRateLimiter, BruteForceProtection } from '../rate-limit';
import type { Session } from '../../types';
import type { SessionStorageAdapter } from '../../session/storage/storage-adapter';
import type { CSRFStorageAdapter } from './storage';

interface SessionWithCSRF {
  csrf?: Record<string, { token: string; expiresAt?: number }>;
  [key: string]: unknown;
}

describe('Module Integration', () => {
  let storage: UniversalMemoryStorage;

  beforeEach(() => {
    storage = new UniversalMemoryStorage();
  });

  describe('Session + CSRF Integration', () => {
    it('should use same storage for sessions and CSRF', async () => {
      // Create session
      const session = createSession('user-123', {
        expiresIn: 3600000, // 1 hour
      });

      // Store session
      await storage.set(session.id, session, 3600000);

      // Use SessionCSRFAdapter to store CSRF in session
      const csrfAdapter = new SessionCSRFAdapter(
        storage as unknown as SessionStorageAdapter<SessionWithCSRF>,
        session.id
      );

      // Generate CSRF token
      const { token } = await generateSynchronizerToken({
        session,
        storage: csrfAdapter,
      });

      expect(token).toBeDefined();

      // Validate CSRF token
      const result = await validateSynchronizerToken(token, {
        session,
        storage: csrfAdapter,
      });

      expect(result.valid).toBe(true);

      // Verify CSRF token is stored in session
      const sessionData = (await storage.get(session.id)) as Session & {
        csrf?: Record<string, unknown>;
      };
      expect(sessionData.csrf).toBeDefined();
      expect(sessionData.csrf?.[`csrf:${session.id}`]).toBeDefined();
    });

    it('should use direct storage for CSRF without session wrapper', async () => {
      const session = createSession('user-456');

      // Use storage directly for CSRF (not in session)
      const { token } = await generateSynchronizerToken({
        session,
        storage: storage as unknown as CSRFStorageAdapter, // Use UniversalMemoryStorage directly
      });

      const result = await validateSynchronizerToken(token, {
        session,
        storage: storage as unknown as CSRFStorageAdapter,
      });

      expect(result.valid).toBe(true);
    });
  });

  describe('Session + Rate Limiting Integration', () => {
    it('should use same storage for sessions and rate limiting', async () => {
      // Create session
      const session = createSession('user-789');
      await storage.set(session.id, session, 3600000);

      // Create rate limiter with same storage
      const limiter = createRateLimiter({
        storage, // Same universal storage!
        max: 5,
        window: 60000, // 1 minute
      });

      // Make 5 requests (all should be allowed since limit is 5)
      for (let i = 0; i < 5; i++) {
        const result = await limiter(session.userId);
        expect(result.allowed).toBe(true);
        expect(result.limit).toBe(5);
      }

      // 6th request should be blocked
      const blocked = await limiter(session.userId);
      expect(blocked.allowed).toBe(false);
      expect(blocked.retryAfter).toBeGreaterThan(0);
    });

    it('should track brute force attempts per session', async () => {
      const session = createSession('user-999');
      await storage.set(session.id, session, 3600000);

      const bruteForce = new BruteForceProtection({
        storage, // Same storage!
        maxAttempts: 3,
        lockoutDuration: 900000, // 15 min
      });

      const key = `login:${session.userId}`;

      // Record 3 failed attempts (matching maxAttempts)
      // Each recordFailedAttempt returns the result AFTER recording
      const result1 = await bruteForce.recordFailedAttempt(key);
      expect(result1.attemptsRemaining).toBe(2);

      const result2 = await bruteForce.recordFailedAttempt(key);
      expect(result2.attemptsRemaining).toBe(1);

      const result3 = await bruteForce.recordFailedAttempt(key);
      expect(result3.allowed).toBe(false); // 3rd attempt triggers lockout
      expect(result3.lockedUntil).toBeDefined();
    });
  });

  describe('Full Stack Integration', () => {
    it('should handle session + CSRF + rate limiting together', async () => {
      // 1. Create and store session
      const session = createSession('user-full-stack', {
        expiresIn: 3600000,
      });
      await storage.set(session.id, session, 3600000);

      // 2. Setup CSRF protection
      const csrfAdapter = new SessionCSRFAdapter(
        storage as unknown as SessionStorageAdapter<SessionWithCSRF>,
        session.id
      );
      const { token: csrfToken } = await generateSynchronizerToken({
        session,
        storage: csrfAdapter,
      });

      // 3. Setup rate limiting
      const limiter = createRateLimiter({
        storage,
        max: 100,
        window: 60000,
      });

      // 4. Simulate authenticated request with CSRF protection
      const rateLimit = await limiter(session.userId);
      expect(rateLimit.allowed).toBe(true);

      const csrfValid = await validateSynchronizerToken(csrfToken, {
        session,
        storage: csrfAdapter,
      });
      expect(csrfValid.valid).toBe(true);

      // 5. Verify session still exists
      const sessionData = await storage.get(session.id);
      expect(sessionData).toBeDefined();
      expect((sessionData as Session).userId).toBe(session.userId);

      // All three modules working with same storage!
      expect(storage.size()).toBeGreaterThan(0);
    });

    it('should share storage statistics across modules', async () => {
      const session1 = createSession('user-1');
      const session2 = createSession('user-2');

      await storage.set(session1.id, session1, 3600000);
      await storage.set(session2.id, session2, 3600000);

      const csrfAdapter1 = new SessionCSRFAdapter(
        storage as unknown as SessionStorageAdapter<SessionWithCSRF>,
        session1.id
      );
      await generateSynchronizerToken({
        session: session1,
        storage: csrfAdapter1,
      });

      const limiter = createRateLimiter({ storage, max: 10, window: 60000 });
      await limiter('user-1');
      await limiter('user-2');

      // All data stored in same storage instance
      // Sessions (2) + CSRF in session1 + rate limit counters (2)
      expect(storage.size()).toBeGreaterThan(2);
    });
  });

  describe('Storage Cleanup', () => {
    it('should cleanup expired entries from all modules', async () => {
      // Add session with short TTL
      const session = createSession('temp-user');
      await storage.set(session.id, session, 100); // 100ms TTL

      // Add CSRF token with expiration
      await storage.set('csrf:test', 'token-123', 100);

      // Add rate limit counter
      await storage.increment('rate:test');

      expect(storage.size()).toBe(3);

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 150));

      // Cleanup
      const cleaned = await storage.cleanup!();

      expect(cleaned).toBe(2); // Session and CSRF expired, counter has no TTL
      expect(storage.size()).toBe(1); // Only rate counter remains
    });
  });
});
