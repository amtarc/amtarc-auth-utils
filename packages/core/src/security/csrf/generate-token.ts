/**
 * CSRF token generation utilities
 * Provides secure, unpredictable tokens for CSRF protection
 */

import crypto from 'crypto';

export interface CSRFTokenOptions {
  /** Token length in bytes (default: 32) */
  length?: number;
  /** Token encoding (default: 'base64url') */
  encoding?: 'base64url' | 'hex' | 'base64';
  /** Include timestamp for automatic expiration */
  includeTimestamp?: boolean;
  /** Token lifetime in milliseconds (if timestamp included) */
  lifetime?: number;
}

/**
 * Generate a cryptographically secure CSRF token
 */
export function generateCSRFToken(options: CSRFTokenOptions = {}): string {
  const {
    length = 32,
    encoding = 'base64url',
    includeTimestamp = false,
    lifetime,
  } = options;

  const randomBytes = crypto.randomBytes(length);

  if (includeTimestamp) {
    const timestamp = Date.now();
    const lifetimeMs = lifetime || 3600000; // 1 hour default
    const expiresAt = timestamp + lifetimeMs;

    // Format: timestamp.expiresAt.randomToken
    const token = `${timestamp}.${expiresAt}.${randomBytes.toString(encoding)}`;
    return token;
  }

  return randomBytes.toString(encoding);
}

/**
 * Generate a CSRF token paired with a secret
 * Used for double-submit cookie pattern
 */
export function generateCSRFTokenPair(options: CSRFTokenOptions = {}): {
  token: string;
  secret: string;
} {
  const token = generateCSRFToken(options);
  const secret = generateCSRFToken(options);
  return { token, secret };
}

/**
 * Generate CSRF token hash for storage
 * Prevents token leakage via storage
 */
export function hashCSRFToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('base64url');
}
