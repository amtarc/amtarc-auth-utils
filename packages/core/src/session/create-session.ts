import type { Session, SessionOptions, User } from '../types';
import { randomBytes } from 'crypto';

/**
 * Generates a secure random session ID
 */
function generateSessionId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = randomBytes(16).toString('hex');
  return `session_${timestamp}_${randomPart}`;
}

/**
 * Creates a new session for a user
 *
 * @param userId - The user ID to create a session for
 * @param options - Session configuration options
 * @returns A new session object
 *
 * @example
 * ```ts
 * const session = createSession('user-123', {
 *   expiresIn: 1000 * 60 * 60 * 24, // 24 hours
 *   idleTimeout: 1000 * 60 * 30, // 30 minutes
 * });
 * ```
 */
export function createSession<TUser extends User = User>(
  userId: string,
  options: SessionOptions = {}
): Session<TUser> {
  const now = new Date();
  const expiresIn = options.expiresIn ?? 1000 * 60 * 60 * 24 * 7; // 7 days default

  const session: Session<TUser> = {
    id: generateSessionId(),
    userId,
    expiresAt: new Date(now.getTime() + expiresIn),
    createdAt: now,
    lastActiveAt: now,
  };

  if (options.fingerprint) {
    session.metadata = { fingerprint: true };
  }

  return session;
}
