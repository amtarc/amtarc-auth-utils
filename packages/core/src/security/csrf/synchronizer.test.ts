/**
 * Synchronizer CSRF Pattern Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateSynchronizerToken,
  validateSynchronizerToken,
} from './synchronizer';
import { MemoryCSRFStorage } from './storage';

describe('Synchronizer Pattern', () => {
  let storage: MemoryCSRFStorage;

  beforeEach(() => {
    storage = new MemoryCSRFStorage();
  });

  describe('generateSynchronizerToken', () => {
    it('should generate synchronizer token', async () => {
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
        lastActiveAt: new Date(),
      };

      const result = await generateSynchronizerToken({
        session,
        storage,
      });

      expect(result.token).toBeDefined();
      expect(result.sessionUpdated).toBe(true);

      const stored = await storage.get(`csrf:${session.id}`);
      expect(stored).toBe(result.token);
    });

    it('should reuse token when regenerate is per-session', async () => {
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
        lastActiveAt: new Date(),
      };

      const result1 = await generateSynchronizerToken({
        session,
        storage,
        regenerate: 'per-session',
      });

      const result2 = await generateSynchronizerToken({
        session,
        storage,
        regenerate: 'per-session',
      });

      expect(result1.token).toBe(result2.token);
    });

    it('should regenerate token when regenerate is per-request', async () => {
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
        lastActiveAt: new Date(),
      };

      const result1 = await generateSynchronizerToken({
        session,
        storage,
        regenerate: 'per-request',
      });

      const result2 = await generateSynchronizerToken({
        session,
        storage,
        regenerate: 'per-request',
      });

      expect(result1.token).not.toBe(result2.token);
    });
  });

  describe('validateSynchronizerToken', () => {
    it('should validate synchronizer token', async () => {
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
        lastActiveAt: new Date(),
      };

      const { token } = await generateSynchronizerToken({
        session,
        storage,
      });

      const result = await validateSynchronizerToken(token, {
        session,
        storage,
      });

      expect(result.valid).toBe(true);
    });

    it('should reject invalid synchronizer token', async () => {
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 86400000),
        lastActiveAt: new Date(),
      };

      await generateSynchronizerToken({ session, storage });

      const result = await validateSynchronizerToken('invalid-token', {
        session,
        storage,
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBeDefined();
    });
  });
});
