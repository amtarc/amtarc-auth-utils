/**
 * @amtarc/auth-utils - Multi-Device Session Management Tests
 */

/* eslint-disable no-undef */
import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  listUserSessions,
  revokeDeviceSession,
  enforceConcurrentSessionLimit,
  countUserSessions,
  findSessionByDevice,
} from './multi-device';
import { UnauthorizedSessionAccessError } from '../errors';
import { MemoryStorageAdapter } from './storage/memory-storage';
import type { Session } from '../types';

describe('listUserSessions', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should list all sessions for a user', async () => {
    const now = Date.now();

    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(now - 3600000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 1800000),
      metadata: {
        device: { name: 'iPhone', type: 'mobile' },
        ip: '192.168.1.1',
      },
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(now - 1800000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 100),
      metadata: {
        device: { name: 'MacBook', type: 'laptop' },
        ip: '192.168.1.2',
      },
    });

    const sessions = await listUserSessions('123', storage);

    expect(sessions).toHaveLength(2);
    expect(sessions[0].id).toBe('session-2'); // Most recent first
    expect(sessions[1].id).toBe('session-1');
  });

  it('should mark current session', async () => {
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

    const sessions = await listUserSessions('123', storage, {
      currentSessionId: 'session-1',
    });

    expect(sessions.find((s) => s.id === 'session-1')?.current).toBe(true);
    expect(sessions.find((s) => s.id === 'session-2')?.current).toBe(false);
  });

  it('should include device information', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: {
        device: {
          name: 'iPad Pro',
          type: 'tablet',
          os: 'iOS 17',
        },
        ip: '10.0.0.1',
      },
    });

    const sessions = await listUserSessions('123', storage);

    expect(sessions[0].device).toEqual({
      name: 'iPad Pro',
      type: 'tablet',
      os: 'iOS 17',
    });
    expect(sessions[0].ip).toBe('10.0.0.1');
  });

  it('should return empty array for user with no sessions', async () => {
    const sessions = await listUserSessions('non-existent', storage);
    expect(sessions).toEqual([]);
  });

  it('should sort sessions by last active desc', async () => {
    const now = Date.now();

    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(now - 3600000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 3000000), // Oldest
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(now - 2000000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 1000000), // Middle
    });

    await storage.set('session-3', {
      id: 'session-3',
      userId: '123',
      createdAt: new Date(now - 1000000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 100), // Newest
    });

    const sessions = await listUserSessions('123', storage);

    expect(sessions[0].id).toBe('session-3'); // Newest first
    expect(sessions[1].id).toBe('session-2');
    expect(sessions[2].id).toBe('session-1'); // Oldest last
  });

  it('should filter out expired sessions', async () => {
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
    ); // Expired

    await new Promise((resolve) => setTimeout(resolve, 100));

    const sessions = await listUserSessions('123', storage);

    expect(sessions).toHaveLength(1);
    expect(sessions[0].id).toBe('session-1');
  });
});

describe('revokeDeviceSession', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should revoke a session', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    await revokeDeviceSession('123', 'session-1', storage);

    const session = await storage.get('session-1');
    expect(session).toBeNull();
  });

  it('should throw when revoking session of another user', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    await expect(
      revokeDeviceSession('456', 'session-1', storage)
    ).rejects.toThrow(UnauthorizedSessionAccessError);

    // Session should still exist
    const session = await storage.get('session-1');
    expect(session).not.toBeNull();
  });

  it('should not throw when session does not exist', async () => {
    await expect(
      revokeDeviceSession('123', 'non-existent', storage)
    ).resolves.toBeUndefined();
  });

  it('should not throw when session already expired', async () => {
    await storage.set(
      'session-1',
      {
        id: 'session-1',
        userId: '123',
        createdAt: new Date(),
        expiresAt: new Date(Date.now() - 1000),
        lastActiveAt: new Date(),
      },
      { ttl: 0.01 }
    );

    await new Promise((resolve) => setTimeout(resolve, 100));

    await expect(
      revokeDeviceSession('123', 'session-1', storage)
    ).resolves.toBeUndefined();
  });
});

describe('enforceConcurrentSessionLimit', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should remove oldest session when over limit', async () => {
    const now = Date.now();

    // Create 3 sessions
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(now - 3000000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 3000000), // Oldest
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(now - 2000000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 2000000), // Middle
    });

    await storage.set('session-3', {
      id: 'session-3',
      userId: '123',
      createdAt: new Date(now - 1000000),
      expiresAt: new Date(now + 3600000),
      lastActiveAt: new Date(now - 100), // Newest
    });

    // Enforce limit of 2
    const removed = await enforceConcurrentSessionLimit('123', storage, 2);

    expect(removed).toBe(1);

    // Oldest session should be removed
    expect(await storage.exists('session-1')).toBe(false);

    // Other sessions should remain
    expect(await storage.exists('session-2')).toBe(true);
    expect(await storage.exists('session-3')).toBe(true);
  });

  it('should return 0 when under limit', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    const removed = await enforceConcurrentSessionLimit('123', storage, 5);

    expect(removed).toBe(0);
    expect(await storage.exists('session-1')).toBe(true);
  });

  it('should remove multiple sessions if needed', async () => {
    const now = Date.now();

    // Create 5 sessions
    for (let i = 1; i <= 5; i++) {
      await storage.set(`session-${i}`, {
        id: `session-${i}`,
        userId: '123',
        createdAt: new Date(now - i * 1000000),
        expiresAt: new Date(now + 3600000),
        lastActiveAt: new Date(now - i * 1000000),
      });
    }

    // Enforce limit of 2
    const removed = await enforceConcurrentSessionLimit('123', storage, 2);

    expect(removed).toBe(3);

    // Only 2 newest should remain
    expect(await storage.exists('session-1')).toBe(true);
    expect(await storage.exists('session-2')).toBe(true);
    expect(await storage.exists('session-3')).toBe(false);
    expect(await storage.exists('session-4')).toBe(false);
    expect(await storage.exists('session-5')).toBe(false);
  });

  it('should handle expired sessions', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

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

    await new Promise((resolve) => setTimeout(resolve, 100));

    const removed = await enforceConcurrentSessionLimit('123', storage, 1);

    // Should not remove any - only 1 valid session exists
    expect(removed).toBe(0);
  });
});

describe('countUserSessions', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should count user sessions', async () => {
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

    const count = await countUserSessions('123', storage);
    expect(count).toBe(2);
  });

  it('should return 0 for user with no sessions', async () => {
    const count = await countUserSessions('non-existent', storage);
    expect(count).toBe(0);
  });
});

describe('findSessionByDevice', () => {
  let storage: MemoryStorageAdapter<Session>;

  beforeEach(() => {
    storage = new MemoryStorageAdapter();
  });

  afterEach(() => {
    storage.destroy();
  });

  it('should find session by device type', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: { device: { type: 'mobile', name: 'iPhone' } },
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: { device: { type: 'laptop', name: 'MacBook' } },
    });

    const session = await findSessionByDevice('123', storage, {
      type: 'mobile',
    });

    expect(session?.id).toBe('session-1');
  });

  it('should find session by device name', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: { device: { name: 'iPad Pro' } },
    });

    const session = await findSessionByDevice('123', storage, {
      name: 'iPad Pro',
    });

    expect(session?.id).toBe('session-1');
  });

  it('should find session by multiple criteria', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: {
        device: {
          type: 'mobile',
          name: 'iPhone 15',
          os: 'iOS 17',
        },
      },
    });

    const session = await findSessionByDevice('123', storage, {
      type: 'mobile',
      os: 'iOS 17',
    });

    expect(session?.id).toBe('session-1');
  });

  it('should return null when device not found', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: { device: { type: 'laptop' } },
    });

    const session = await findSessionByDevice('123', storage, {
      type: 'mobile',
    });

    expect(session).toBeNull();
  });

  it('should return null when session has no device metadata', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
    });

    const session = await findSessionByDevice('123', storage, {
      type: 'mobile',
    });

    expect(session).toBeNull();
  });

  it('should return first matching session', async () => {
    await storage.set('session-1', {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: { device: { type: 'mobile' } },
    });

    await storage.set('session-2', {
      id: 'session-2',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 3600000),
      lastActiveAt: new Date(),
      metadata: { device: { type: 'mobile' } },
    });

    const session = await findSessionByDevice('123', storage, {
      type: 'mobile',
    });

    // Should return first match
    expect(session).not.toBeNull();
    const device = session?.metadata?.device as { type?: string } | undefined;
    expect(device?.type).toBe('mobile');
  });
});

describe('UnauthorizedSessionAccessError', () => {
  it('should create error with default message', () => {
    const error = new UnauthorizedSessionAccessError();

    expect(error.name).toBe('UnauthorizedSessionAccessError');
    expect(error.message).toBe('Unauthorized session access');
  });

  it('should create error with custom message', () => {
    const error = new UnauthorizedSessionAccessError('Custom error');

    expect(error.name).toBe('UnauthorizedSessionAccessError');
    expect(error.message).toBe('Custom error');
  });
});
