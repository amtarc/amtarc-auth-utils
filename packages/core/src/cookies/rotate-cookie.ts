/**
 * @amtarc/auth-utils - Cookie Rotation
 * Utilities for rotating cookie values securely
 */

import type { CookieOptions } from '../types';
import { createAuthCookie } from './create-cookie';
import { deleteAuthCookie } from './delete-cookie';

/**
 * Result of cookie rotation
 */
export interface CookieRotationResult {
  /** New cookie to set */
  set: string;
  /** Old cookie to delete (if different path/domain) */
  delete?: string;
}

/**
 * Rotate a cookie value (create new, optionally delete old)
 *
 * @example
 * ```typescript
 * const rotation = rotateCookie('session', newSessionId, {
 *   httpOnly: true,
 *   secure: true
 * });
 *
 * res.setHeader('Set-Cookie', [rotation.set, rotation.delete].filter(Boolean));
 * ```
 */
export function rotateCookie(
  name: string,
  newValue: string,
  options?: CookieOptions & {
    /**
     * Whether to explicitly delete the old cookie
     * Useful if path or domain changed
     */
    deleteOld?: boolean;
    /**
     * Path of the old cookie to delete
     */
    oldPath?: string;
    /**
     * Domain of the old cookie to delete
     */
    oldDomain?: string;
  }
): CookieRotationResult {
  const { deleteOld, oldPath, oldDomain, ...cookieOptions } = options || {};

  const set = createAuthCookie(name, newValue, cookieOptions);

  const result: CookieRotationResult = { set };

  // If explicitly requested or if path/domain changed, delete old cookie
  if (deleteOld || oldPath || oldDomain) {
    const deleteOptions: { path?: string; domain?: string } = {};

    const finalPath = oldPath || cookieOptions.path;
    const finalDomain = oldDomain || cookieOptions.domain;

    if (finalPath !== undefined) {
      deleteOptions.path = finalPath;
    }

    if (finalDomain !== undefined) {
      deleteOptions.domain = finalDomain;
    }

    result.delete = deleteAuthCookie(name, deleteOptions);
  }

  return result;
}

/**
 * Rotate multiple cookies at once
 *
 * @example
 * ```typescript
 * const cookies = rotateCookies([
 *   { name: 'session', value: newSessionId },
 *   { name: 'csrf', value: newCsrfToken }
 * ]);
 *
 * const headers = cookies.flatMap(c => [c.set, c.delete].filter(Boolean));
 * res.setHeader('Set-Cookie', headers);
 * ```
 */
export function rotateCookies(
  cookies: Array<{
    name: string;
    newValue: string;
    options?: CookieOptions & {
      deleteOld?: boolean;
      oldPath?: string;
      oldDomain?: string;
    };
  }>
): CookieRotationResult[] {
  return cookies.map(({ name, newValue, options }) =>
    rotateCookie(name, newValue, options)
  );
}

/**
 * Helper to rotate a signed cookie
 *
 * @example
 * ```typescript
 * const rotation = rotateSignedCookie('session', newValue, secret, options);
 * ```
 */
export function rotateSignedCookie(
  name: string,
  newValue: string,
  secret: string,
  options?: CookieOptions & {
    deleteOld?: boolean;
    oldPath?: string;
    oldDomain?: string;
  }
): CookieRotationResult {
  const { signCookie } = require('./sign-cookie');
  const signed = signCookie(newValue, secret);
  return rotateCookie(name, signed, options);
}

/**
 * Helper to rotate an encrypted cookie
 *
 * @example
 * ```typescript
 * const rotation = rotateEncryptedCookie('token', newValue, secret, options);
 * ```
 */
export function rotateEncryptedCookie(
  name: string,
  newValue: string,
  secret: string,
  options?: CookieOptions & {
    deleteOld?: boolean;
    oldPath?: string;
    oldDomain?: string;
  }
): CookieRotationResult {
  const { encryptCookie } = require('./encrypt-cookie');
  const encrypted = encryptCookie(newValue, secret);
  return rotateCookie(name, encrypted, options);
}

/**
 * Check if cookie rotation is needed based on age
 *
 * @example
 * ```typescript
 * const created = new Date('2024-01-01');
 * const maxAge = 86400; // 24 hours
 *
 * if (shouldRotateCookie(created, maxAge)) {
 *   // Rotate the cookie
 * }
 * ```
 */
export function shouldRotateCookie(
  createdAt: Date,
  maxAge: number,
  rotationThreshold: number = 0.5 // Rotate when 50% of lifetime passed
): boolean {
  const age = Date.now() - createdAt.getTime();
  const maxAgeMs = maxAge * 1000;
  const rotationPoint = maxAgeMs * rotationThreshold;

  return age >= rotationPoint;
}
