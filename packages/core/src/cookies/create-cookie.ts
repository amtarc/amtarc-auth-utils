/**
 * @amtarc/auth-utils - Cookie Creation
 * Create secure HTTP cookies with proper defaults
 */

import type { CookieOptions } from '../types';

/**
 * Create a secure HTTP cookie with proper defaults
 *
 * @example
 * ```typescript
 * const cookie = createAuthCookie('session', 'abc123', {
 *   httpOnly: true,
 *   secure: true,
 *   sameSite: 'lax',
 *   maxAge: 86400 // 24 hours
 * });
 *
 * // Set in response
 * res.setHeader('Set-Cookie', cookie);
 * ```
 */
export function createAuthCookie(
  name: string,
  value: string,
  options?: CookieOptions
): string {
  // Secure defaults
  const defaults: Required<Omit<CookieOptions, 'domain' | 'expires'>> = {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 86400, // 24 hours
    signed: false,
    encrypted: false,
  };

  const opts = { ...defaults, ...options };

  let cookie = `${encodeURIComponent(name)}=${encodeURIComponent(value)}`;

  // Max-Age takes precedence over Expires
  if (options?.expires && options?.maxAge === undefined) {
    // Only Expires was provided, use it
    cookie += `; Expires=${options.expires.toUTCString()}`;
  } else if (opts.maxAge !== undefined && opts.maxAge >= 0) {
    // maxAge was explicitly set (including 0 for deletion)
    cookie += `; Max-Age=${opts.maxAge}`;
    // For deletion cookies (maxAge=0), use epoch; otherwise calculate from now
    const expires =
      opts.maxAge === 0 && options?.expires
        ? options.expires
        : new Date(Date.now() + opts.maxAge * 1000);
    cookie += `; Expires=${expires.toUTCString()}`;
  }

  cookie += `; Path=${opts.path}`;

  if (options?.domain) {
    cookie += `; Domain=${options.domain}`;
  }

  if (opts.httpOnly) {
    cookie += '; HttpOnly';
  }

  if (opts.secure) {
    cookie += '; Secure';
  }

  if (opts.sameSite) {
    const sameSite =
      opts.sameSite.charAt(0).toUpperCase() + opts.sameSite.slice(1);
    cookie += `; SameSite=${sameSite}`;
  }

  return cookie;
}

/**
 * Create multiple cookies at once
 *
 * @example
 * ```typescript
 * const cookies = createAuthCookies([
 *   { name: 'session', value: 'abc123' },
 *   { name: 'csrf', value: 'def456', httpOnly: false }
 * ]);
 *
 * res.setHeader('Set-Cookie', cookies);
 * ```
 */
export function createAuthCookies(
  cookies: Array<{ name: string; value: string } & CookieOptions>
): string[] {
  return cookies.map(({ name, value, ...options }) =>
    createAuthCookie(name, value, options)
  );
}

/**
 * Validate cookie name (RFC 6265)
 * Cookie names cannot contain control characters, whitespace, or separators
 */
export function isValidCookieName(name: string): boolean {
  if (!name || name.length === 0) return false;

  // RFC 6265: cookie-name = token
  // token = 1*<any CHAR except CTLs or separators>
  // separators = "(" | ")" | "<" | ">" | "@" | "," | ";" | ":" | "\" |
  //              """ | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP | HT
  // eslint-disable-next-line no-control-regex
  const invalidChars = /[\x00-\x20\x7F()<>@,;:\\"/[\]?={}]/;

  return !invalidChars.test(name);
}

/**
 * Validate cookie value (RFC 6265)
 */
export function isValidCookieValue(value: string): boolean {
  // Cookie values should be printable ASCII characters
  // excluding whitespace, comma, semicolon, and backslash
  // eslint-disable-next-line no-control-regex
  const invalidChars = /[\x00-\x20\x7F,;\\]/;

  return !invalidChars.test(value);
}

/**
 * Estimate cookie size in bytes
 * Useful to ensure cookies stay under 4KB limit
 */
export function estimateCookieSize(
  name: string,
  value: string,
  options?: CookieOptions
): number {
  const cookie = createAuthCookie(name, value, options);
  // eslint-disable-next-line no-undef
  return new TextEncoder().encode(cookie).length;
}
