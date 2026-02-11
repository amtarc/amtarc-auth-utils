/**
 * @amtarc/auth-utils - Memory Storage Tests
 */

/* eslint-disable no-undef */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { MemoryStorageAdapter } from './memory-storage';

describe('MemoryStorageAdapter', () => {
  let storage: MemoryStorageAdapter;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  describe('set and get', () => {
    it('should store and retrieve session data', async () => {
      const sessionData = { userId: '123', name: 'Test User' };
      await storage.set('session-1', sessionData);

      const retrieved = await storage.get('session-1');
      expect(retrieved).toEqual(sessionData);
    });

    it('should return null for non-existent session', async () => {
      const retrieved = await storage.get('non-existent');
      expect(retrieved).toBeNull();
    });

    it('should store session with custom TTL', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData, { ttl: 1 }); // 1 second

      // Should exist immediately
      const retrieved = await storage.get('session-1');
      expect(retrieved).toEqual(sessionData);
    });

    it('should store session with metadata', async () => {
      const sessionData = { userId: '123' };
      const metadata = { ip: '127.0.0.1', userAgent: 'Test' };

      await storage.set('session-1', sessionData, { metadata });

      const retrieved = await storage.get('session-1');
      expect(retrieved).toEqual(sessionData);
    });
  });

  describe('expiration', () => {
    it('should return null for expired session', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData, { ttl: 0.1 }); // 100ms

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 150));

      const retrieved = await storage.get('session-1');
      expect(retrieved).toBeNull();
    });

    it('should delete expired session on get', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData, { ttl: 0.1 });

      await new Promise((resolve) => setTimeout(resolve, 150));
      await storage.get('session-1');

      const exists = await storage.exists('session-1');
      expect(exists).toBe(false);
    });

    it('should use default TTL when not specified', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData);

      // Should still exist after 1 second (default is 24 hours)
      await new Promise((resolve) => setTimeout(resolve, 1000));

      const retrieved = await storage.get('session-1');
      expect(retrieved).toEqual(sessionData);
    });
  });

  describe('delete', () => {
    it('should delete a session', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData);
      await storage.delete('session-1');

      const retrieved = await storage.get('session-1');
      expect(retrieved).toBeNull();
    });

    it('should not throw when deleting non-existent session', async () => {
      await expect(storage.delete('non-existent')).resolves.toBeUndefined();
    });

    it('should remove session from user tracking on delete', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData);
      await storage.delete('session-1');

      const userSessions = await storage.getUserSessions('123');
      expect(userSessions).toHaveLength(0);
    });
  });

  describe('touch', () => {
    it('should extend session TTL', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData, { ttl: 1 }); // 1 second

      // Extend TTL before expiration
      await new Promise((resolve) => setTimeout(resolve, 500));
      await storage.touch('session-1', 10); // Extend to 10 seconds

      // Wait past original expiration
      await new Promise((resolve) => setTimeout(resolve, 700));

      const retrieved = await storage.get('session-1');
      expect(retrieved).toEqual(sessionData);
    });

    it('should not throw  when touching non-existent session', async () => {
      await expect(storage.touch('non-existent', 10)).resolves.toBeUndefined();
    });
  });

  describe('exists', () => {
    it('should return true for existing session', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData);

      const exists = await storage.exists('session-1');
      expect(exists).toBe(true);
    });

    it('should return false for non-existent session', async () => {
      const exists = await storage.exists('non-existent');
      expect(exists).toBe(false);
    });

    it('should return false for expired session', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData, { ttl: 0.1 });

      await new Promise((resolve) => setTimeout(resolve, 150));

      const exists = await storage.exists('session-1');
      expect(exists).toBe(false);
    });

    it('should delete expired session when checking existence', async () => {
      const sessionData = { userId: '123' };
      await storage.set('session-1', sessionData, { ttl: 0.1 });

      await new Promise((resolve) => setTimeout(resolve, 150));
      await storage.exists('session-1');

      const stats = storage.getStats();
      expect(stats.totalSessions).toBe(0);
    });
  });

  describe('user session tracking', () => {
    it('should track multiple sessions per user', async () => {
      await storage.set('session-1', { userId: '123', device: 'phone' });
      await storage.set('session-2', { userId: '123', device: 'laptop' });
      await storage.set('session-3', { userId: '456', device: 'desktop' });

      const user123Sessions = await storage.getUserSessions('123');
      const user456Sessions = await storage.getUserSessions('456');

      expect(user123Sessions).toHaveLength(2);
      expect(user123Sessions).toContain('session-1');
      expect(user123Sessions).toContain('session-2');
      expect(user456Sessions).toHaveLength(1);
      expect(user456Sessions).toContain('session-3');
    });

    it('should return empty array for user with no sessions', async () => {
      const sessions = await storage.getUserSessions('non-existent');
      expect(sessions).toEqual([]);
    });

    it('should filter out expired sessions from user sessions', async () => {
      await storage.set('session-1', { userId: '123' }, { ttl: 10 });
      await storage.set('session-2', { userId: '123' }, { ttl: 0.1 });

      await new Promise((resolve) => setTimeout(resolve, 150));

      const sessions = await storage.getUserSessions('123');
      expect(sessions).toHaveLength(1);
      expect(sessions).toContain('session-1');
    });

    it('should delete all sessions for a user', async () => {
      await storage.set('session-1', { userId: '123' });
      await storage.set('session-2', { userId: '123' });
      await storage.set('session-3', { userId: '456' });

      await storage.deleteUserSessions('123');

      const user123Sessions = await storage.getUserSessions('123');
      const user456Sessions = await storage.getUserSessions('456');

      expect(user123Sessions).toHaveLength(0);
      expect(user456Sessions).toHaveLength(1); // Unaffected
    });

    it('should not throw when deleting sessions for non-existent user', async () => {
      await expect(
        storage.deleteUserSessions('non-existent')
      ).resolves.toBeUndefined();
    });
  });

  describe('cleanup', () => {
    it('should remove expired sessions', async () => {
      await storage.set('session-1', { userId: '123' }, { ttl: 0.1 });
      await storage.set('session-2', { userId: '456' }, { ttl: 10 });

      await new Promise((resolve) => setTimeout(resolve, 150));

      const cleaned = await storage.cleanup();

      expect(cleaned).toBe(1);
      expect(await storage.exists('session-1')).toBe(false);
      expect(await storage.exists('session-2')).toBe(true);
    });

    it('should return 0 when no sessions need cleanup', async () => {
      await storage.set('session-1', { userId: '123' }, { ttl: 10 });

      const cleaned = await storage.cleanup();
      expect(cleaned).toBe(0);
    });

    it('should handle empty storage', async () => {
      const cleaned = await storage.cleanup();
      expect(cleaned).toBe(0);
    });
  });

  describe('auto cleanup', () => {
    it('should automatically cleanup expired sessions', async () => {
      const autoStorage = new MemoryStorageAdapter({
        autoCleanup: true,
        cleanupInterval: 100, // 100ms
      });

      await autoStorage.set('session-1', { userId: '123' }, { ttl: 0.05 });

      // Wait for expiration and auto-cleanup
      await new Promise((resolve) => setTimeout(resolve, 200));

      const stats = autoStorage.getStats();
      expect(stats.totalSessions).toBe(0);

      autoStorage.destroy();
    });
  });

  describe('getStats', () => {
    it('should return correct statistics', async () => {
      await storage.set('session-1', { userId: '123' });
      await storage.set('session-2', { userId: '123' });
      await storage.set('session-3', { userId: '456' });

      const stats = storage.getStats();

      expect(stats.totalSessions).toBe(3);
      expect(stats.totalUsers).toBe(2);
      expect(stats.memoryUsage).toBeGreaterThan(0);
    });

    it('should return zero stats for empty storage', () => {
      const stats = storage.getStats();

      expect(stats.totalSessions).toBe(0);
      expect(stats.totalUsers).toBe(0);
      expect(stats.memoryUsage).toBe(0);
    });
  });

  describe('destroy', () => {
    it('should clear all sessions', async () => {
      await storage.set('session-1', { userId: '123' });
      await storage.set('session-2', { userId: '456' });

      storage.destroy();

      const stats = storage.getStats();
      expect(stats.totalSessions).toBe(0);
      expect(stats.totalUsers).toBe(0);
    });

    it('should stop auto-cleanup interval', async () => {
      const autoStorage = new MemoryStorageAdapter({
        autoCleanup: true,
        cleanupInterval: 100,
      });

      autoStorage.destroy();

      // If interval is not cleared, this test may hang
      await new Promise((resolve) => setTimeout(resolve, 150));
    });
  });
});
