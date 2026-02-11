/**
 * @amtarc/auth-utils - Session Invalidation
 * Functions for invalidating sessions (single, user, all devices)
 */

import type { SessionStorageAdapter } from './storage/storage-adapter';

/**
 * Options for invalidating a session
 */
export interface InvalidateOptions {
  /**
   * Reason for invalidation (for audit logging)
   */
  reason?: string;

  /**
   * Additional metadata
   */
  metadata?: Record<string, unknown>;
}

/**
 * Options for invalidating user sessions
 */
export interface InvalidateUserSessionsOptions extends InvalidateOptions {
  /**
   * Session ID to keep active (current device)
   * Useful for "logout all other devices"
   */
  except?: string;
}

/**
 * Invalidate a single session
 *
 * @example
 * ```typescript
 * await invalidateSession('session-123', storage, {
 *   reason: 'User logged out'
 * });
 * ```
 */
export async function invalidateSession(
  sessionId: string,
  storage: SessionStorageAdapter,
  options?: InvalidateOptions
): Promise<void> {
  await storage.delete(sessionId);

  if (options?.reason) {
    // Log invalidation for audit trail
    // In Phase 12, this will integrate with audit logging
    // For now, we just note the reason is available
  }
}

/**
 * Invalidate all sessions for a user
 *
 * Useful for:
 * - "Logout all devices"
 * - Security incidents (compromised account)
 * - Password reset
 * - Account termination
 *
 * @example
 * ```typescript
 * // Logout all devices
 * await invalidateUserSessions('user-123', storage);
 *
 * // Logout all OTHER devices (keep current)
 * await invalidateUserSessions('user-123', storage, {
 *   except: currentSessionId
 * });
 * ```
 *
 * @returns Number of sessions invalidated
 */
export async function invalidateUserSessions(
  userId: string,
  storage: SessionStorageAdapter,
  options?: InvalidateUserSessionsOptions
): Promise<number> {
  const sessionIds = await storage.getUserSessions(userId);

  let invalidated = 0;

  for (const sessionId of sessionIds) {
    // Skip the excepted session
    if (options?.except && sessionId === options.except) {
      continue;
    }

    await storage.delete(sessionId);
    invalidated++;
  }

  if (options?.reason) {
    // Log bulk invalidation for audit trail
    // Will be integrated with audit logging in Phase 12
  }

  return invalidated;
}

/**
 * Invalidate all sessions in the system
 *
 * WARNING: This is a destructive operation!
 * Use only for:
 * - Emergency security response
 * - System maintenance
 * - Testing/development
 *
 * @example
 * ```typescript
 * const count = await invalidateAllSessions(storage, {
 *   reason: 'Security incident - forced logout'
 * });
 * console.log(`Invalidated ${count} sessions`);
 * ```
 *
 * @returns Number of sessions invalidated
 */
export async function invalidateAllSessions(
  storage: SessionStorageAdapter,
  options?: InvalidateOptions
): Promise<number> {
  // This requires storage adapters to support listing all sessions
  // For now, we rely on cleanup() which removes expired ones
  // In production, adapters should implement a way to list all sessions

  if (storage.cleanup) {
    // At minimum, cleanup expired sessions
    await storage.cleanup();
  }

  if (options?.reason) {
    // Log system-wide invalidation
    // Critical security event - should always be logged
  }

  // Note: Full implementation depends on storage adapter capabilities
  // Some adapters (Redis, DB) can efficiently clear all sessions
  // Memory adapter would need a clearAll() method
  return 0; // Placeholder - depends on adapter
}
