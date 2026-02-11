import type { Session, SessionOptions, User } from '../types';

/**
 * Validation result
 */
export interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'idle-timeout' | 'invalid';
  shouldRefresh?: boolean;
}

/**
 * Validates a session
 *
 * @param session - The session to validate
 * @param options - Validation options
 * @returns Validation result
 *
 * @example
 * ```ts
 * const result = validateSession(session, {
 *   idleTimeout: 1000 * 60 * 30, // 30 minutes
 * });
 *
 * if (!result.valid) {
 *   throw new SessionExpiredError(result.reason);
 * }
 * ```
 */
export function validateSession<TUser extends User = User>(
  session: Session<TUser>,
  options: SessionOptions = {}
): ValidationResult {
  const now = new Date();

  // Check if session structure is valid
  if (!session.id || !session.userId || !session.expiresAt) {
    return { valid: false, reason: 'invalid' };
  }

  // Check absolute expiration
  if (now > session.expiresAt) {
    return { valid: false, reason: 'expired' };
  }

  // Check idle timeout
  if (options.idleTimeout && session.lastActiveAt) {
    const idleTime = now.getTime() - session.lastActiveAt.getTime();
    if (idleTime > options.idleTimeout) {
      return { valid: false, reason: 'idle-timeout' };
    }
  }

  // Check if session should be refreshed (>50% through its lifetime)
  const totalLifetime =
    session.expiresAt.getTime() - session.createdAt.getTime();
  const elapsed = now.getTime() - session.createdAt.getTime();
  const shouldRefresh = elapsed > totalLifetime * 0.5;

  return { valid: true, shouldRefresh };
}
