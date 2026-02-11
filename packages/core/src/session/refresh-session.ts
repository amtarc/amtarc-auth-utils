/**
 * @amtarc/auth-utils - Session Refresh & Rotation
 * Functions for extending session lifetime and rotating session IDs
 */

import { randomBytes } from 'node:crypto';
import type {
  SessionStorageAdapter,
  StorageOptions,
} from './storage/storage-adapter';
import { SessionNotFoundError } from '../errors';
import type { Session } from '../types';

/**
 * Options for refreshing a session
 */
export interface RefreshSessionOptions {
  /**
   * New TTL in seconds
   * @default 3600 (1 hour)
   */
  ttl?: number;

  /**
   * Whether to rotate the session ID for security
   * Recommended after privilege escalation or sensitive operations
   * @default false
   */
  rotateId?: boolean;

  /**
   * Update last active timestamp
   * @default true
   */
  updateLastActive?: boolean;
}

/**
 * Refresh a session with new expiration time
 *
 * @example
 * ```typescript
 * const refreshed = await refreshSession('session-123', storage, {
 *   ttl: 7200, // 2 hours
 *   rotateId: false
 * });
 * ```
 */
export async function refreshSession<T extends Session = Session>(
  sessionId: string,
  storage: SessionStorageAdapter<T>,
  options?: RefreshSessionOptions
): Promise<T> {
  const session = await storage.get(sessionId);

  if (!session) {
    throw new SessionNotFoundError(sessionId);
  }

  // Update last active time
  if (options?.updateLastActive !== false) {
    session.lastActiveAt = new Date();
  }

  const ttl = options?.ttl || 3600;

  // Rotate session ID if requested
  if (options?.rotateId) {
    const newSessionId = generateSessionId();
    await storage.set(newSessionId, session, { ttl });
    await storage.delete(sessionId);

    return {
      ...session,
      id: newSessionId,
    } as T;
  }

  // Just extend TTL
  await storage.touch(sessionId, ttl);

  return session;
}

/**
 * Rotate session ID for security (OWASP recommendation)
 *
 * Should be called after:
 * - Login
 * - Privilege escalation
 * - Password change
 * - Any sensitive operation
 *
 * @example
 * ```typescript
 * const newSessionId = await rotateSessionId('old-session-123', storage);
 * // Update cookie/header with newSessionId
 * ```
 */
export async function rotateSessionId<T extends Session = Session>(
  sessionId: string,
  storage: SessionStorageAdapter<T>,
  options?: Pick<StorageOptions, 'ttl'>
): Promise<string> {
  const session = await storage.get(sessionId);

  if (!session) {
    throw new SessionNotFoundError(sessionId);
  }

  const newSessionId = generateSessionId();

  // Copy session with new ID
  await storage.set(newSessionId, session, {
    ttl: options?.ttl || 3600,
  });

  // Delete old session
  await storage.delete(sessionId);

  return newSessionId;
}

/**
 * Generate a cryptographically secure session ID
 *
 * @param length - Number of bytes (default: 32 = 256 bits)
 * @returns Base64url encoded session ID
 */
export function generateSessionId(length: number = 32): string {
  return randomBytes(length).toString('base64url');
}
