/**
 * @amtarc/auth-utils - Multi-Device Session Management
 * Functions for managing sessions across multiple devices
 */

import type { SessionStorageAdapter } from './storage/storage-adapter';
import type { Session } from '../types';
import { UnauthorizedSessionAccessError } from '../errors';

/**
 * Information about a user's session
 */
export interface SessionInfo {
  /** Session ID */
  id: string;
  /** User ID */
  userId: string;
  /** When session was created */
  createdAt: Date;
  /** Last activity timestamp */
  lastActiveAt: Date;
  /** Device information */
  device?: {
    name?: string;
    type?: string;
    os?: string;
    browser?: string;
  };
  /** IP address */
  ip?: string;
  /** Whether this is the current session */
  current: boolean;
}

/**
 * Options for listing user sessions
 */
export interface ListUserSessionsOptions {
  /**
   * Current session ID to mark as current
   */
  currentSessionId?: string;

  /**
   * Include extended session details
   */
  includeMetadata?: boolean;
}

/**
 * List all active sessions for a user
 *
 * Useful for:
 * - "Active sessions" view in user settings
 * - Security audit of logged-in devices
 * - "Logout from other devices" feature
 *
 * @example
 * ```typescript
 * const sessions = await listUserSessions('user-123', storage, {
 *   currentSessionId: req.sessionId
 * });
 *
 * // Show user their active devices
 * sessions.forEach(session => {
 *   console.log(`${session.device?.name} - Last active: ${session.lastActiveAt}`);
 *   if (!session.current) {
 *     console.log('  [Logout button]');
 *   }
 * });
 * ```
 */
export async function listUserSessions<T extends Session = Session>(
  userId: string,
  storage: SessionStorageAdapter<T>,
  options?: ListUserSessionsOptions
): Promise<SessionInfo[]> {
  const sessionIds = await storage.getUserSessions(userId);

  const sessions = await Promise.all(
    sessionIds.map(async (id) => {
      const data = await storage.get(id);
      if (!data) return null;

      return {
        id,
        userId: data.userId,
        createdAt: data.createdAt,
        lastActiveAt: data.lastActiveAt,
        device: data.metadata?.device,
        ip: data.metadata?.ip,
        current: options?.currentSessionId === id,
      } as SessionInfo;
    })
  );

  // Filter out null sessions and sort by last active (newest first)
  return sessions
    .filter((s): s is SessionInfo => s !== null)
    .sort((a, b) => b.lastActiveAt.getTime() - a.lastActiveAt.getTime());
}

/**
 * Revoke a specific device session
 *
 * Security: Validates that the session belongs to the specified user
 *
 * @example
 * ```typescript
 * // User clicks "Logout" on a specific device in their session list
 * await revokeDeviceSession('user-123', 'session-laptop', storage);
 * ```
 */
export async function revokeDeviceSession<T extends Session = Session>(
  userId: string,
  sessionId: string,
  storage: SessionStorageAdapter<T>
): Promise<void> {
  const session = await storage.get(sessionId);

  if (!session) {
    // Session doesn't exist - already revoked or expired
    return;
  }

  if (session.userId !== userId) {
    throw new UnauthorizedSessionAccessError(
      `User ${userId} cannot revoke session ${sessionId} belonging to user ${session.userId}`
    );
  }

  await storage.delete(sessionId);
}

/**
 * Check and enforce concurrent session limit
 *
 * When a user has too many concurrent sessions, removes the oldest one
 *
 * @example
 * ```typescript
 * // After creating a new session, enforce limit
 * await enforceConcurrentSessionLimit('user-123', storage, 5);
 * // If user had 5+ sessions, oldest one is now removed
 * ```
 *
 * @returns Number of sessions removed (0 or 1)
 */
export async function enforceConcurrentSessionLimit<
  T extends Session = Session,
>(
  userId: string,
  storage: SessionStorageAdapter<T>,
  limit: number
): Promise<number> {
  const sessionIds = await storage.getUserSessions(userId);

  // Check if over limit
  if (sessionIds.length <= limit) {
    return 0;
  }

  // Get all session data
  const sessionDataList = await Promise.all(
    sessionIds.map(async (id) => {
      const data = await storage.get(id);
      return { id, data };
    })
  );

  // Filter out null/expired sessions and sort by last active
  const validSessions = sessionDataList
    .filter((s) => s.data !== null)
    .sort((a, b) => {
      const aTime = a.data?.lastActiveAt?.getTime() || 0;
      const bTime = b.data?.lastActiveAt?.getTime() || 0;
      return aTime - bTime; // Oldest first
    });

  // Calculate how many to remove
  const removeCount = validSessions.length - limit;
  let removed = 0;

  // Remove oldest sessions
  for (let i = 0; i < removeCount; i++) {
    const session = validSessions[i];
    if (session) {
      await storage.delete(session.id);
      removed++;
    }
  }

  return removed;
}

/**
 * Count active sessions for a user
 *
 * @example
 * ```typescript
 * const count = await countUserSessions('user-123', storage);
 * if (count > 10) {
 *   console.log('User has many active sessions - possible security issue');
 * }
 * ```
 */
export async function countUserSessions(
  userId: string,
  storage: SessionStorageAdapter
): Promise<number> {
  const sessionIds = await storage.getUserSessions(userId);
  return sessionIds.length;
}

/**
 * Find session by device information
 *
 * @example
 * ```typescript
 * const session = await findSessionByDevice('user-123', storage, {
 *   type: 'mobile',
 *   name: 'iPhone'
 * });
 * ```
 */
export async function findSessionByDevice<T extends Session = Session>(
  userId: string,
  storage: SessionStorageAdapter<T>,
  deviceQuery: {
    type?: string;
    name?: string;
    os?: string;
  }
): Promise<T | null> {
  const sessionIds = await storage.getUserSessions(userId);

  for (const sessionId of sessionIds) {
    const session = await storage.get(sessionId);
    if (!session || !session.metadata?.device) continue;

    const device = session.metadata.device as
      | { type?: string; name?: string; os?: string; browser?: string }
      | undefined;

    // Check if device matches query
    const matches =
      (!deviceQuery.type || device?.type === deviceQuery.type) &&
      (!deviceQuery.name || device?.name === deviceQuery.name) &&
      (!deviceQuery.os || device?.os === deviceQuery.os);

    if (matches) {
      return session;
    }
  }

  return null;
}
