/**
 * @amtarc/auth-utils - Composable Guards
 * Utilities for combining multiple guards with AND/OR logic
 */

import type { GuardContext, GuardFunction, GuardResult } from './require-auth';

/**
 * Require ANY of the provided guards to pass (OR logic)
 *
 * Returns success if at least one guard passes.
 * Returns failure only if all guards fail.
 *
 * @example
 * ```typescript
 * // Allow if user is authenticated OR has API key
 * const guard = requireAny([
 *   requireAuth(),
 *   requireApiKey()
 * ]);
 * ```
 */
export function requireAny<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T> {
  return async (context: GuardContext): Promise<GuardResult<T>> => {
    if (guards.length === 0) {
      return {
        authorized: false,
        message: 'No guards provided to requireAny',
      };
    }

    const results = await Promise.allSettled(
      guards.map((guard) => guard(context))
    );

    // If any guard passed, return success
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.authorized) {
        return result.value;
      }
    }

    // All guards failed - collect error messages
    const messages: string[] = [];
    for (const result of results) {
      if (result.status === 'fulfilled' && result.value.message) {
        messages.push(result.value.message);
      } else if (result.status === 'rejected') {
        messages.push(result.reason?.message || 'Guard check failed');
      }
    }

    return {
      authorized: false,
      message:
        messages.length > 0
          ? `None of the required conditions were met: ${messages.join(', ')}`
          : 'None of the required conditions were met',
    };
  };
}

/**
 * Require ALL of the provided guards to pass (AND logic)
 *
 * Returns success only if all guards pass.
 * Returns failure if any guard fails.
 *
 * @example
 * ```typescript
 * // Allow only if user is authenticated AND has admin role
 * const guard = requireAll([
 *   requireAuth(),
 *   requireRole('admin')
 * ]);
 * ```
 */
export function requireAll<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T[]> {
  return async (context: GuardContext): Promise<GuardResult<T[]>> => {
    if (guards.length === 0) {
      return {
        authorized: true,
        data: [],
      };
    }

    try {
      const results = await Promise.all(guards.map((guard) => guard(context)));

      // Check if all passed
      const failedGuard = results.find((r) => !r.authorized);

      if (failedGuard) {
        const result: GuardResult<T[]> = {
          authorized: false,
          message: failedGuard.message || 'Guard check failed',
        };
        if (failedGuard.redirect) {
          result.redirect = failedGuard.redirect;
        }
        return result;
      }

      return {
        authorized: true,
        data: results.map((r) => r.data).filter((d): d is T => d !== undefined),
      };
    } catch (error) {
      return {
        authorized: false,
        message: error instanceof Error ? error.message : 'Guard check failed',
      };
    }
  };
}

/**
 * Chain guards with short-circuit evaluation
 *
 * Guards are executed sequentially. If any guard fails, execution stops
 * and the failure is returned immediately.
 *
 * @example
 * ```typescript
 * // Check authentication, then rate limit, then permissions
 * const guard = chainGuards(
 *   requireAuth(),
 *   checkRateLimit(),
 *   requirePermission('read:posts')
 * );
 * ```
 */
export function chainGuards<T = unknown>(
  ...guards: GuardFunction<T>[]
): GuardFunction<T> {
  return async (context: GuardContext): Promise<GuardResult<T>> => {
    if (guards.length === 0) {
      return { authorized: true };
    }

    let lastData: T | undefined;

    for (const guard of guards) {
      const result = await guard(context);

      if (!result.authorized) {
        return result;
      }

      if (result.data !== undefined) {
        lastData = result.data;
      }
    }

    const result: GuardResult<T> = {
      authorized: true,
    };

    if (lastData !== undefined) {
      result.data = lastData;
    }

    return result;
  };
}

/**
 * Create a guard that always passes
 * Useful for conditional logic or testing
 *
 * @example
 * ```typescript
 * const guard = allowAll();
 * ```
 */
export function allowAll<T = unknown>(data?: T): GuardFunction<T> {
  return async (): Promise<GuardResult<T>> => {
    const result: GuardResult<T> = {
      authorized: true,
    };

    if (data !== undefined) {
      result.data = data;
    }

    return result;
  };
}

/**
 * Create a guard that always fails
 * Useful for maintenance mode or testing
 *
 * @example
 * ```typescript
 * const guard = denyAll({ message: 'Service under maintenance' });
 * ```
 */
export function denyAll(options?: {
  message?: string;
  redirect?: string;
}): GuardFunction<never> {
  return async (): Promise<GuardResult<never>> => {
    const result: GuardResult<never> = {
      authorized: false,
      message: options?.message || 'Access denied',
    };

    if (options?.redirect) {
      result.redirect = options.redirect;
    }

    return result;
  };
}

/**
 * Conditional guard - apply guard only if condition is met
 *
 * @example
 * ```typescript
 * // Only require auth in production
 * const guard = conditionalGuard(
 *   () => process.env.NODE_ENV === 'production',
 *   requireAuth()
 * );
 * ```
 */
export function conditionalGuard<T = unknown>(
  condition: boolean | (() => boolean | Promise<boolean>),
  guard: GuardFunction<T>,
  fallback?: GuardFunction<T>
): GuardFunction<T> {
  return async (context: GuardContext): Promise<GuardResult<T>> => {
    const shouldApply =
      typeof condition === 'function' ? await condition() : condition;

    if (shouldApply) {
      return guard(context);
    }

    if (fallback) {
      return fallback(context);
    }

    return { authorized: true };
  };
}
