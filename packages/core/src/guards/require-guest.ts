/**
 * @amtarc/auth-utils - Require Guest Guard
 * Guard that requires user to NOT be authenticated
 */

import type { GuardContext, GuardFunction, GuardResult } from './require-auth';

import { AlreadyAuthenticatedError } from '../errors';

/**
 * Options for requireGuest guard
 */
export interface RequireGuestOptions {
  /**
   * Redirect URL if already authenticated (e.g., dashboard)
   * If provided, returns redirect instead of throwing error
   */
  redirect?: string;

  /**
   * Custom error message
   */
  message?: string;
}

/**
 * Guard that requires user to NOT be authenticated
 * Useful for login/register pages
 *
 * @example
 * ```typescript
 * const guard = requireGuest({
 *   redirect: '/dashboard'
 * });
 *
 * const result = await guard({
 *   getSession: () => getSessionFromCookie(req)
 * });
 *
 * if (!result.authorized) {
 *   return redirect(result.redirect); // Already logged in
 * }
 * ```
 */
export function requireGuest(
  options?: RequireGuestOptions
): GuardFunction<null> {
  return async (context: GuardContext): Promise<GuardResult<null>> => {
    const session = await context.getSession();

    if (session) {
      if (options?.redirect) {
        return {
          authorized: false,
          redirect: options.redirect,
          message: options?.message || 'Already authenticated',
        };
      }

      throw new AlreadyAuthenticatedError(options?.message);
    }

    return {
      authorized: true,
      data: null,
    };
  };
}
