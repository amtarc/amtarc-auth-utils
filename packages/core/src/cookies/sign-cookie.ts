/**
 * @amtarc/auth-utils - Cookie Signing
 * Sign and verify cookies using HMAC for integrity
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import type { CookieOptions } from '../types';

/**
 * Sign a cookie value using HMAC-SHA256
 *
 * Prevents tampering by creating a cryptographic signature
 *
 * @example
 * ```typescript
 * const signed = signCookie('user-123', 'my-secret-key');
 * // Returns: "user-123.signature"
 *
 * const cookie = createAuthCookie('userId', signed);
 * ```
 */
export function signCookie(value: string, secret: string): string {
  if (!value) {
    throw new Error('Cookie value cannot be empty');
  }

  if (!secret || secret.length < 32) {
    throw new Error('Secret must be at least 32 characters');
  }

  const signature = createHmac('sha256', secret)
    .update(value)
    .digest('base64url');

  return `${value}.${signature}`;
}

/**
 * Unsign and verify a signed cookie
 *
 * Returns the original value if signature is valid, null otherwise
 *
 * @example
 * ```typescript
 * const original = unsignCookie(signedValue, 'my-secret-key');
 * if (original) {
 *   // Signature is valid, use original value
 * } else {
 *   // Cookie was tampered with
 * }
 * ```
 */
export function unsignCookie(
  signedValue: string,
  secret: string
): string | null {
  if (!signedValue) {
    return null;
  }

  const lastDotIndex = signedValue.lastIndexOf('.');

  if (lastDotIndex === -1) {
    return null; // Not a signed cookie
  }

  const value = signedValue.slice(0, lastDotIndex);
  const providedSignature = signedValue.slice(lastDotIndex + 1);

  if (!value || !providedSignature) {
    return null;
  }

  try {
    const expectedSignature = createHmac('sha256', secret)
      .update(value)
      .digest('base64url');

    // Constant-time comparison to prevent timing attacks
    if (
      !timingSafeEqual(
        Buffer.from(providedSignature),
        Buffer.from(expectedSignature)
      )
    ) {
      return null;
    }

    return value;
  } catch {
    return null;
  }
}

/**
 * Verify a signed cookie without extracting the value
 *
 * @example
 * ```typescript
 * if (verifyCookieSignature(signedValue, secret)) {
 *   // Cookie is valid and untampered
 * }
 * ```
 */
export function verifyCookieSignature(
  signedValue: string,
  secret: string
): boolean {
  return unsignCookie(signedValue, secret) !== null;
}

/**
 * Sign a cookie and create the Set-Cookie header in one step
 *
 * @example
 * ```typescript
 * const cookie = signAndCreateCookie('session', 'abc123', 'secret', {
 *   httpOnly: true,
 *   secure: true
 * });
 *
 * res.setHeader('Set-Cookie', cookie);
 * ```
 */
export function signAndCreateCookie(
  name: string,
  value: string,
  secret: string,
  options?: CookieOptions
): string {
  const signed = signCookie(value, secret);
  // Import dynamically to avoid circular dependency
  const { createAuthCookie } = require('./create-cookie');
  return createAuthCookie(name, signed, options);
}

/**
 * Error thrown when cookie signature verification fails
 */
export class CookieSignatureError extends Error {
  constructor(message = 'Invalid cookie signature') {
    super(message);
    this.name = 'CookieSignatureError';
  }
}

/**
 * Unsign cookie with strict mode that throws on invalid signature
 *
 * @example
 * ```typescript
 * try {
 *   const value = unsignCookieStrict(signedValue, secret);
 *   // Use value
 * } catch (err) {
 *   // Cookie was tampered with
 * }
 * ```
 */
export function unsignCookieStrict(
  signedValue: string,
  secret: string
): string {
  const value = unsignCookie(signedValue, secret);

  if (value === null) {
    throw new CookieSignatureError('Cookie signature verification failed');
  }

  return value;
}
