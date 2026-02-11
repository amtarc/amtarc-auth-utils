/**
 * @amtarc/auth-utils - Cookie Encryption
 * Encrypt and decrypt cookies using AES-256-GCM for confidentiality
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
} from 'node:crypto';
import type { CookieOptions } from '../types';

/**
 * Encrypt a cookie value using AES-256-GCM
 *
 * Provides both confidentiality and authenticity
 *
 * @example
 * ```typescript
 * const encrypted = encryptCookie('sensitive-data', 'my-secret-key');
 * const cookie = createAuthCookie('data', encrypted);
 * ```
 */
export function encryptCookie(value: string, secret: string): string {
  if (!value) {
    throw new Error('Cookie value cannot be empty');
  }

  if (!secret || secret.length < 32) {
    throw new Error('Secret must be at least 32 characters');
  }

  // Derive a 256-bit key from the secret
  const key = createHash('sha256').update(secret).digest();

  // Generate a random 12-byte IV (recommended for GCM)
  const iv = randomBytes(12);

  const cipher = createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(value, 'utf8', 'base64url');
  encrypted += cipher.final('base64url');

  // Get the authentication tag
  const authTag = cipher.getAuthTag().toString('base64url');

  // Format: iv.encrypted.authTag
  return `${iv.toString('base64url')}.${encrypted}.${authTag}`;
}

/**
 * Decrypt an encrypted cookie
 *
 * Returns the original value if decryption succeeds, null otherwise
 *
 * @example
 * ```typescript
 * const decrypted = decryptCookie(encryptedValue, 'my-secret-key');
 * if (decrypted) {
 *   // Decryption successful, use original value
 * } else {
 *   // Cookie was tampered with or key is wrong
 * }
 * ```
 */
export function decryptCookie(
  encryptedValue: string,
  secret: string
): string | null {
  if (!encryptedValue) {
    return null;
  }

  try {
    const parts = encryptedValue.split('.');

    if (parts.length !== 3) {
      return null; // Invalid format
    }

    const [ivB64, encryptedB64, authTagB64] = parts;

    if (!ivB64 || !encryptedB64 || !authTagB64) {
      return null;
    }

    // Derive the same key
    const key = createHash('sha256').update(secret).digest();
    const iv = Buffer.from(ivB64, 'base64url');
    const authTag = Buffer.from(authTagB64, 'base64url');

    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    let decrypted = decipher.update(encryptedB64, 'base64url', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  } catch {
    // Decryption failed (wrong key, tampered data, etc.)
    return null;
  }
}

/**
 * Verify if an encrypted cookie can be decrypted
 *
 * Does not return the decrypted value
 */
export function verifyEncryptedCookie(
  encryptedValue: string,
  secret: string
): boolean {
  return decryptCookie(encryptedValue, secret) !== null;
}

/**
 * Encrypt a cookie and create the Set-Cookie header in one step
 *
 * @example
 * ```typescript
 * const cookie = encryptAndCreateCookie('token', 'abc123', 'secret', {
 *   httpOnly: true,
 *   secure: true
 * });
 *
 * res.setHeader('Set-Cookie', cookie);
 * ```
 */
export function encryptAndCreateCookie(
  name: string,
  value: string,
  secret: string,
  options?: CookieOptions
): string {
  const encrypted = encryptCookie(value, secret);
  const { createAuthCookie } = require('./create-cookie');
  return createAuthCookie(name, encrypted, options);
}

/**
 * Error thrown when cookie decryption fails
 */
export class CookieDecryptionError extends Error {
  constructor(message = 'Cookie decryption failed') {
    super(message);
    this.name = 'CookieDecryptionError';
  }
}

/**
 * Decrypt cookie with strict mode that throws on failure
 *
 * @example
 * ```typescript
 * try {
 *   const value = decryptCookieStrict(encryptedValue, secret);
 *   // Use value
 * } catch (err) {
 *   // Decryption failed
 * }
 * ```
 */
export function decryptCookieStrict(
  encryptedValue: string,
  secret: string
): string {
  const value = decryptCookie(encryptedValue, secret);

  if (value === null) {
    throw new CookieDecryptionError(
      'Cookie decryption failed - invalid data or wrong secret'
    );
  }

  return value;
}
