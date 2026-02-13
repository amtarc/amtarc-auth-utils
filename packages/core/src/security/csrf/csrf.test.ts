/**
 * CSRF Protection Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateCSRFToken,
  validateCSRFToken,
  generateDoubleSubmitToken,
  validateDoubleSubmitToken,
  generateSynchronizerToken,
  validateSynchronizerToken,
  MemoryCSRFStorage,
} from '.';

describe('CSRF Protection', () => {
  describe('generateCSRFToken', () => {
    it('should generate a token with default options', () => {
      const token = generateCSRFToken();
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);
    });

    it('should generate tokens with specified length', () => {
      const token = generateCSRFToken({ length: 64 });
      // base64url encoding makes the string longer than raw bytes
      expect(token.length).toBeGreaterThan(60);
    });

    it('should support different encodings', () => {
      const hexToken = generateCSRFToken({ encoding: 'hex' });
      expect(hexToken).toMatch(/^[0-9a-f]+$/);

      const base64Token = generateCSRFToken({ encoding: 'base64' });
      expect(base64Token).toMatch(/^[A-Za-z0-9+/]+=*$/);

      const base64urlToken = generateCSRFToken({ encoding: 'base64url' });
      expect(base64urlToken).toMatch(/^[A-Za-z0-9_-]+$/);
    });

    it('should generate timestamped tokens', () => {
      const token = generateCSRFToken({ includeTimestamp: true });
      const parts = token.split('.');
      expect(parts.length).toBe(3);
      expect(parseInt(parts[0]!)).toBeGreaterThan(0);
    });
  });

  describe('validateCSRFToken', () => {
    let storage: MemoryCSRFStorage;

    beforeEach(() => {
      storage = new MemoryCSRFStorage();
    });

    it('should validate a stored token', async () => {
      const token = generateCSRFToken();
      await storage.set('test-key', token);

      const result = await validateCSRFToken(token, {
        storage,
        key: 'test-key',
      });

      expect(result.valid).toBe(true);
    });

    it('should reject invalid tokens', async () => {
      await storage.set('test-key', 'valid-token');

      const result = await validateCSRFToken('invalid-token', {
        storage,
        key: 'test-key',
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('mismatch');
    });

    it('should validate timestamped tokens', async () => {
      const token = generateCSRFToken({
        includeTimestamp: true,
        lifetime: 60000,
      });

      await storage.set('test-key', token);

      const result = await validateCSRFToken(token, {
        storage,
        key: 'test-key',
      });

      expect(result.valid).toBe(true);
    });

    it('should reject expired timestamped tokens', async () => {
      const pastTime = Date.now() - 120000; // 2 minutes ago
      const expiresAt = pastTime + 60000; // expired 1 minute ago
      const token = `${pastTime}.${expiresAt}.test-token`;

      await storage.set('test-key', token);

      const result = await validateCSRFToken(token, {
        storage,
        key: 'test-key',
      });

      expect(result.valid).toBe(false);
      expect(result.reason).toBe('expired');
    });

    it('should delete token after use when deleteAfterUse is true', async () => {
      const token = generateCSRFToken();
      await storage.set('test-key', token);

      await validateCSRFToken(token, {
        storage,
        key: 'test-key',
        deleteAfterUse: true,
      });

      const exists = await storage.has('test-key');
      expect(exists).toBe(false);
    });
  });

  describe('Double Submit Pattern', () => {
    it('should generate double submit token', () => {
      const result = generateDoubleSubmitToken();

      expect(result.token).toBeDefined();
      expect(result.cookie).toBeDefined();
      expect(result.cookie).toContain('__Host-csrf');
      expect(result.cookie).toContain(result.token);
      expect(result.cookie).toContain('HttpOnly');
      expect(result.cookie).toContain('Secure');
      expect(result.cookie).toContain('SameSite=strict');
    });

    it('should validate matching tokens', () => {
      const token = 'test-csrf-token';

      const result = validateDoubleSubmitToken(token, token);
      expect(result.valid).toBe(true);
    });

    it('should reject non-matching tokens', () => {
      const result = validateDoubleSubmitToken('token1', 'token2');
      expect(result.valid).toBe(false);
    });

    it('should reject missing tokens', () => {
      const result = validateDoubleSubmitToken(undefined as any, 'token');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('missing');
    });
  });

  describe('Synchronizer Pattern', () => {
    let storage: MemoryCSRFStorage;

    beforeEach(() => {
      storage = new MemoryCSRFStorage();
    });

    it('should generate synchronizer token', async () => {
      const now = new Date();
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        lastActiveAt: now,
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
      const now = new Date();
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        lastActiveAt: now,
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
      const now = new Date();
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        lastActiveAt: now,
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

    it('should validate synchronizer token', async () => {
      const now = new Date();
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        lastActiveAt: now,
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
      const now = new Date();
      const session = {
        id: 'session-123',
        userId: 'user-1',
        createdAt: now,
        expiresAt: new Date(now.getTime() + 3600000),
        lastActiveAt: now,
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

  describe('MemoryCSRFStorage', () => {
    let storage: MemoryCSRFStorage;

    beforeEach(() => {
      storage = new MemoryCSRFStorage();
    });

    it('should store and retrieve tokens', async () => {
      await storage.set('key1', 'token1');
      const token = await storage.get('key1');
      expect(token).toBe('token1');
    });

    it('should return null for non-existent keys', async () => {
      const token = await storage.get('non-existent');
      expect(token).toBeNull();
    });

    it('should delete tokens', async () => {
      await storage.set('key1', 'token1');
      await storage.delete('key1');
      const token = await storage.get('key1');
      expect(token).toBeNull();
    });

    it('should check token existence', async () => {
      await storage.set('key1', 'token1');
      expect(await storage.has('key1')).toBe(true);
      expect(await storage.has('key2')).toBe(false);
    });

    it('should expire tokens', async () => {
      await storage.set('key1', 'token1', 100); // TTL: 100ms
      expect(await storage.get('key1')).toBe('token1');

      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(await storage.get('key1')).toBeNull();
    });

    it('should cleanup expired tokens', async () => {
      await storage.set('key1', 'token1', 50); // TTL: 50ms
      await storage.set('key2', 'token2'); // no expiry

      await new Promise((resolve) => setTimeout(resolve, 100));
      storage['cleanup']();

      expect(await storage.get('key1')).toBeNull();
      expect(await storage.get('key2')).toBe('token2');
    });
  });
});
