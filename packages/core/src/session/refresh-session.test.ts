/**
 * @amtarc/auth-utils - Session Refresh Tests
 */

/* eslint-disable no-undef */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  refreshSession,
  rotateSessionId,
  generateSessionId,
} from './refresh-session';
import { SessionNotFoundError } from '../errors';
import { MemoryStorageAdapter } from './storage/memory-storage';
import type { Session } from '../types';

describe('refreshSession', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  describe('basic refresh', () => {
    it('should refresh a session with new TTL', async () => {
      const session: Session = {
        id: 'session-1',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 1000),
        lastActiveAt: new Date(),
      };

      await storage.set('session-1', session, { ttl: 1 });

      const refreshed = await refreshSession('session-1', storage, { ttl: 10 });

      expect(refreshed.id).toBe('session-1');
      expect(refreshed.userId).toBe('123');

      // Wait past original expiration
      await new Promise((resolve) => setTimeout(resolve, 1200));

      // Should still exist due to refresh
      const retrieved = await storage.get('session-1');
      expect(retrieved).not.toBeNull();
    });

    it('should update last active time', async () => {
      const oldDate = new Date(Date.now() - 1000);
      const session: Session = {
        id: 'session-1',
        userId: '123',
        createdAt: oldDate,
        expiresAt: new Date(Date.now() + 3600000),
        lastActiveAt: oldDate,
      };

      await storage.set('session-1', session);

      const refreshed = await refreshSession('session-1', storage);

      expect(refreshed.lastActiveAt.getTime()).toBeGreaterThan(
        oldDate.getTime()
      );
    });

    it('should not update last active when disabled', async () => {
      const oldDate = new Date(Date.now() - 1000);
      const session: Session = {
        id: 'session-1',
        userId: '123',
        createdAt: oldDate,
        expiresAt: new Date(Date.now() + 3600000),
        lastActiveAt: oldDate,
      };

      await storage.set('session-1', session);

      const refreshed = await refreshSession('session-1', storage, {
        updateLastActive: false,
      });

      expect(refreshed.lastActiveAt.getTime()).toBe(oldDate.getTime());
    });

    it('should use default TTL of 1 hour', async () => {
      const session: Session = {
        id: 'session-1',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 1000),
        lastActiveAt: new Date(),
      };

      await storage.set('session-1', session, { ttl: 1 });

      await refreshSession('session-1', storage);

      // After 2 seconds, should still exist (default is 3600s)
      await new Promise((resolve) => setTimeout(resolve, 2000));

      const exists = await storage.exists('session-1');
      expect(exists).toBe(true);
    });

    it('should throw when session not found', async () => {
      await expect(refreshSession('non-existent', storage)).rejects.toThrow(
        SessionNotFoundError
      );

      await expect(refreshSession('non-existent', storage)).rejects.toThrow(
        'Session non-existent not found'
      );
    });
  });

  describe('ID rotation', () => {
    it('should rotate session ID when requested', async () => {
      const session: Session = {
        id: 'session-1',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        lastActiveAt: new Date(),
      };

      await storage.set('session-1', session);

      const refreshed = await refreshSession('session-1', storage, {
        rotateId: true,
      });

      expect(refreshed.id).not.toBe('session-1');
      expect(refreshed.userId).toBe('123');

      // Old session should be deleted
      const oldSession = await storage.get('session-1');
      expect(oldSession).toBeNull();

      // New session should exist
      const newSession = await storage.get(refreshed.id);
      expect(newSession).not.toBeNull();
      expect(newSession?.userId).toBe('123');
    });

    it('should preserve session data during rotation', async () => {
      const session: Session = {
        id: 'session-1',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        lastActiveAt: new Date(),
        metadata: {
          device: 'mobile',
          ip: '127.0.0.1',
        },
      };

      await storage.set('session-1', session);

      const refreshed = await refreshSession('session-1', storage, {
        rotateId: true,
      });

      expect(refreshed.metadata).toEqual({
        device: 'mobile',
        ip: '127.0.0.1',
      });
    });
  });
});

describe('rotateSessionId', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should rotate session ID', async () => {
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    };

    await storage.set('session-1', session);

    const newSessionId = await rotateSessionId('session-1', storage);

    expect(newSessionId).not.toBe('session-1');
    expect(typeof newSessionId).toBe('string');
    expect(newSessionId.length).toBeGreaterThan(0);

    // Old session should be deleted
    const oldExists = await storage.exists('session-1');
    expect(oldExists).toBe(false);

    // New session should exist with same data
    const newSession = await storage.get(newSessionId);
    expect(newSession?.userId).toBe('123');
  });

  it('should apply custom TTL', async () => {
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 1000),
      lastActiveAt: new Date(),
    };

    await storage.set('session-1', session, { ttl: 1 });

    const newSessionId = await rotateSessionId('session-1', storage, {
      ttl: 10,
    });

    // Wait past original expiration
    await new Promise((resolve) => setTimeout(resolve, 1200));

    const exists = await storage.exists(newSessionId);
    expect(exists).toBe(true);
  });

  it('should throw when session not found', async () => {
    await expect(rotateSessionId('non-existent', storage)).rejects.toThrow(
      SessionNotFoundError
    );
  });

  it('should preserve all session properties', async () => {
    const createdAt = new Date(Date.now() - 1000);
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt,
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: {
        device: 'laptop',
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      },
    };

    await storage.set('session-1', session);

    const newSessionId = await rotateSessionId('session-1', storage);
    const newSession = await storage.get(newSessionId);

    expect(newSession?.userId).toBe('123');
    expect(newSession?.createdAt).toEqual(createdAt);
    expect(newSession?.metadata).toEqual({
      device: 'laptop',
      ip: '192.168.1.1',
      userAgent: 'Mozilla/5.0',
    });
  });
});

describe('generateSessionId', () => {
  it('should generate a session ID', () => {
    const id = generateSessionId();

    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
  });

  it('should generate unique IDs', () => {
    const id1 = generateSessionId();
    const id2 = generateSessionId();
    const id3 = generateSessionId();

    expect(id1).not.toBe(id2);
    expect(id2).not.toBe(id3);
    expect(id1).not.toBe(id3);
  });

  it('should generate IDs of specified length', () => {
    const id16 = generateSessionId(16);
    const id32 = generateSessionId(32);
    const id64 = generateSessionId(64);

    // Base64url encoding: ~1.33x the bytes
    expect(id32.length).toBeGreaterThan(id16.length);
    expect(id64.length).toBeGreaterThan(id32.length);
  });

  it('should use base64url encoding (no + / =)', () => {
    const id = generateSessionId();

    expect(id).not.toMatch(/[+/=]/);
  });

  it('should have high entropy', () => {
    // Generate many IDs and check for uniqueness
    const ids = new Set();
    for (let i = 0; i < 1000; i++) {
      ids.add(generateSessionId());
    }

    expect(ids.size).toBe(1000); // All unique
  });
});
