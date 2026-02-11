/**
 * @amtarc/auth-utils - Require Authentication Guard
 * Guard that requires user to be authenticated
 */

import type { Session } from '../types';
import type { FingerprintMetadata } from '../session/fingerprint';
import { validateFingerprint } from '../session/fingerprint';
import { UnauthenticatedError } from '../errors';

/**
 * Guard context provided to all guards
 */
export interface GuardContext {
  /** Get the current session */
  getSession(): Promise<Session | null>;
  /** Request metadata for fingerprint validation */
  metadata?: FingerprintMetadata;
  /** Framework-specific request object (optional) */
  request?: unknown;
}

/**
 * Result from a guard execution
 */
export interface GuardResult<T = unknown> {
  /** Whether the guard authorized the request */
  authorized: boolean;
  /** Data to pass to the route handler */
  data?: T;
  /** Redirect URL if unauthorized */
  redirect?: string;
  /** Error message if unauthorized */
  message?: string;
}

/**
 * Guard function type
 */
export type GuardFunction<T = unknown> = (
  context: GuardContext
) => Promise<GuardResult<T>>;

/**
 * Options for requireAuth guard
 */
export interface RequireAuthOptions {
  /**
   * Redirect URL if not authenticated
   * If provided, returns redirect instead of throwing error
   */
  redirect?: string;

  /**
   * Custom error message
   */
  message?: string;

  /**
   * Validate session fingerprint for security
   * @default false
   */
  validateFingerprint?: boolean;

  /**
   * Strict fingerprint validation mode
   * @default true
   */
  strictFingerprint?: boolean;
}

/**
 * Guard that requires user to be authenticated
 *
 * @example
 * ```typescript
 * const guard = requireAuth({
 *   redirect: '/login',
 *   validateFingerprint: true
 * });
 *
 * const result = await guard({
 *   getSession: () => getSessionFromCookie(req),
 *   metadata: {
 *     userAgent: req.headers['user-agent'],
 *     ip: req.ip
 *   }
 * });
 *
 * if (!result.authorized) {
 *   return redirect(result.redirect);
 * }
 * ```
 */
export function requireAuth<T = unknown>(
  options?: RequireAuthOptions
): GuardFunction<T> {
  return async (context: GuardContext): Promise<GuardResult<T>> => {
    const session = await context.getSession();

    // Not authenticated
    if (!session) {
      if (options?.redirect) {
        return {
          authorized: false,
          redirect: options.redirect,
          message: options?.message || 'Authentication required',
        };
      }

      throw new UnauthenticatedError(options?.message);
    }

    // Optional fingerprint validation
    if (options?.validateFingerprint && context.metadata) {
      try {
        validateFingerprint(session, context.metadata, {
          strict: options.strictFingerprint ?? true,
        });
      } catch (error) {
        if (options?.redirect) {
          return {
            authorized: false,
            redirect: options.redirect,
            message: 'Session security validation failed',
          };
        }
        throw error;
      }
    }

    return {
      authorized: true,
      data: session.user as T,
    };
  };
}
