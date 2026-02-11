/**
 * @amtarc/auth-utils - Session Invalidation Tests
 */
/* eslint-disable no-undef */ import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  vi,
} from 'vitest';
import {
  invalidateSession,
  invalidateUserSessions,
  invalidateAllSessions,
} from './invalidate-session';
import { MemoryStorageAdapter } from './storage/memory-storage';
import type { Session } from '../types';

describe('invalidateSession', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should invalidate a session', async () => {
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    };

    await storage.set('session-1', session);

    await invalidateSession('session-1', storage);

    const retrieved = await storage.get('session-1');
    expect(retrieved).toBeNull();
  });

  it('should accept invalidation reason', async () => {
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    };

    await storage.set('session-1', session);

    await invalidateSession('session-1', storage, {
      reason: 'User logged out',
    });

    const retrieved = await storage.get('session-1');
    expect(retrieved).toBeNull();
  });

  it('should not throw when invalidating non-existent session', async () => {
    await expect(
      invalidateSession('non-existent', storage)
    ).resolves.toBeUndefined();
  });

  it('should accept metadata', async () => {
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    };

    await storage.set('session-1', session);

    await invalidateSession('session-1', storage, {
      reason: 'Security incident',
      metadata: { incident_id: 'INC-123', severity: 'high' },
    });

    const retrieved = await storage.get('session-1');
    expect(retrieved).toBeNull();
  });
});

describe('invalidateUserSessions', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should invalidate all sessions for a user', async () => {
    // Create multiple sessions for user-123
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    // Create session for other user
    await storage.set('session-3', {
      id: 'session-3',
      userId: '456',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    const count = await invalidateUserSessions('123', storage);

    expect(count).toBe(2);

    // User 123 sessions should be gone
    expect(await storage.get('session-1')).toBeNull();
    expect(await storage.get('session-2')).toBeNull();

    // User 456 session should remain
    expect(await storage.get('session-3')).not.toBeNull();
  });

  it('should keep excepted session active', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    const count = await invalidateUserSessions('123', storage, {
      except: 'session-1',
    });

    expect(count).toBe(1);

    // Session-1 should remain (excepted)
    expect(await storage.get('session-1')).not.toBeNull();

    // Session-2 should be invalidated
    expect(await storage.get('session-2')).toBeNull();
  });

  it('should return 0 when user has no sessions', async () => {
    const count = await invalidateUserSessions('non-existent', storage);
    expect(count).toBe(0);
  });

  it('should accept invalidation reason', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    const count = await invalidateUserSessions('123', storage, {
      reason: 'Password reset',
    });

    expect(count).toBe(1);
    expect(await storage.get('session-1')).toBeNull();
  });

  it('should handle mixed expired and active sessions', async () => {
    // Active session
    await storage.set(
      'session-1',
      {
        id: 'session-1',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        lastActiveAt: new Date(),
      },
      { ttl: 10 }
    );

    // Expired session
    await storage.set(
      'session-2',
      {
        id: 'session-2',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() - 1000),
        lastActiveAt: new Date(),
      },
      { ttl: 0.01 }
    );

    // Wait for session-2 to expire
    await new Promise((resolve) => setTimeout(resolve, 100));

    const count = await invalidateUserSessions('123', storage);

    // Should only count the active session that was invalidated
    // (getUserSessions filters out expired ones)
    expect(count).toBe(1);
  });

  it('should work with "logout all other devices" pattern', async () => {
    // Simulate 3 devices
    const devices = ['mobile', 'laptop', 'desktop'];
    const sessionIds = ['session-mobile', 'session-laptop', 'session-desktop'];

    for (let i = 0; i < devices.length; i++) {
      await storage.set(sessionIds[i], {
        id: sessionIds[i],
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 3600000),
        lastActiveAt: new Date(),
        metadata: { device: devices[i] },
      });
    }

    // User clicks "logout all other devices" on mobile
    const count = await invalidateUserSessions('123', storage, {
      except: 'session-mobile',
      reason: 'User requested logout from other devices',
    });

    expect(count).toBe(2);

    // Mobile session should remain
    const mobileSession = await storage.get('session-mobile');
    expect(mobileSession).not.toBeNull();
    expect(mobileSession?.metadata?.device).toBe('mobile');

    // Other sessions should be gone
    expect(await storage.get('session-laptop')).toBeNull();
    expect(await storage.get('session-desktop')).toBeNull();
  });
});

describe('invalidateAllSessions', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should call cleanup on storage adapter', async () => {
    const cleanupSpy = vi.spyOn(storage, 'cleanup');

    await invalidateAllSessions(storage, {
      reason: 'System maintenance',
    });

    expect(cleanupSpy).toHaveBeenCalled();
  });

  it('should not throw if storage has no cleanup method', async () => {
    // Create a minimal storage without cleanup
    const minimalStorage = {
      get: vi.fn(),
      set: vi.fn(),
      delete: vi.fn(),
      touch: vi.fn(),
      exists: vi.fn(),
      getUserSessions: vi.fn(),
      deleteUserSessions: vi.fn(),
    };

    await expect(
      invalidateAllSessions(minimalStorage as any)
    ).resolves.toBeDefined();
  });

  it('should accept invalidation reason', async () => {
    await expect(
      invalidateAllSessions(storage, {
        reason: 'Security incident',
        metadata: { incident_id: 'INC-456' },
      })
    ).resolves.toBeDefined();
  });
});
