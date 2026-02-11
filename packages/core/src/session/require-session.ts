import type { Session, SessionOptions, User } from '../types';
import { validateSession } from './validate-session';
import { SessionExpiredError } from '../errors';

/**
 * Session handler callback
 */
export type SessionHandler<TUser extends User = User, TResult = unknown> = (
  _session: Session<TUser>
) => TResult | Promise<TResult>;

/**
 * Creates a guard that requires a valid session
 *
 * @param getSession - Function to retrieve the current session
 * @param options - Session options for validation
 * @returns A function that wraps a handler with session validation
 *
 * @example
 * ```ts
 * const guard = requireSession(
 *   async () => getCurrentSession(),
 *   { idleTimeout: 1000 * 60 * 30 }
 * );
 *
 * const handler = guard(async (session) => {
 *   return { userId: session.userId };
 * });
 * ```
 */
export function requireSession<TUser extends User = User>(
  getSession: () => Session<TUser> | Promise<Session<TUser> | null> | null,
  options: SessionOptions = {}
) {
  return function <TResult>(
    handler: SessionHandler<TUser, TResult>
  ): () => Promise<TResult> {
    return async () => {
      const session = await getSession();

      if (!session) {
        throw new SessionExpiredError('No active session found');
      }

      const validation = validateSession(session, options);

      if (!validation.valid) {
        throw new SessionExpiredError(
          `Session ${validation.reason || 'invalid'}`
        );
      }

      return handler(session);
    };
  };
}
