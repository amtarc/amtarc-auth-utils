/**
 * @amtarc/auth-utils - Cookie Deletion
 * Create cookies that delete existing cookies
 */

import type { CookieOptions } from '../types';
import { createAuthCookie } from './create-cookie';

/**
 * Create a Set-Cookie header that deletes a cookie
 *
 * Sets the cookie to an empty value with immediate expiration
 *
 * @example
 * ```typescript
 * const deleteCookie = deleteAuthCookie('session');
 * res.setHeader('Set-Cookie', deleteCookie);
 * ```
 */
export function deleteAuthCookie(
  name: string,
  options?: Pick<CookieOptions, 'path' | 'domain'>
): string {
  return createAuthCookie(name, '', {
    ...options,
    maxAge: 0,
    expires: new Date(0),
    httpOnly: false, // Allow deletion even if original was HttpOnly
    secure: false, // Allow deletion even if original was Secure
  });
}

/**
 * Create multiple cookie deletion headers
 *
 * @example
 * ```typescript
 * const deleteCookies = deleteAuthCookies(['session', 'csrf', 'theme']);
 * res.setHeader('Set-Cookie', deleteCookies);
 * ```
 */
export function deleteAuthCookies(
  names: string[],
  options?: Pick<CookieOptions, 'path' | 'domain'>
): string[] {
  return names.map((name) => deleteAuthCookie(name, options));
}

/**
 * Delete a cookie with specific path and domain
 *
 * Useful when you need to delete cookies set with specific paths/domains
 *
 * @example
 * ```typescript
 * // Delete cookie that was set with specific path
 * const deleteCookie = deleteAuthCookieExact('session', {
 *   path: '/api',
 *   domain: '.example.com'
 * });
 * ```
 */
export function deleteAuthCookieExact(
  name: string,
  options: Required<Pick<CookieOptions, 'path' | 'domain'>>
): string {
  return deleteAuthCookie(name, options);
}

/**
 * Create deletion cookies for all possible path variations
 *
 * Sometimes cookies are set with different paths and you want to ensure they're all deleted
 *
 * @example
 * ```typescript
 * const deletions = deleteAuthCookieAllPaths('session', ['/', '/api', '/admin']);
 * res.setHeader('Set-Cookie', deletions);
 * ```
 */
export function deleteAuthCookieAllPaths(
  name: string,
  paths: string[] = ['/', ''],
  domain?: string
): string[] {
  return paths.map((path) => {
    const opts: { path: string; domain?: string } = { path };
    if (domain !== undefined) {
      opts.domain = domain;
    }
    return deleteAuthCookie(name, opts);
  });
}
