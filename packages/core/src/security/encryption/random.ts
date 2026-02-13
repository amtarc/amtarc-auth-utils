/**
 * Secure random value generation
 */

import { randomBytes, randomInt } from 'crypto';

/**
 * Generate cryptographically secure random bytes
 */
export function generateRandomBytes(size: number): Buffer {
  return randomBytes(size);
}

/**
 * Generate random string with specified encoding
 */
export function generateRandomString(
  size: number,
  encoding: 'hex' | 'base64' | 'base64url' = 'hex'
): string {
  const bytes = randomBytes(size);

  if (encoding === 'base64url') {
    return bytes
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  return bytes.toString(encoding);
}

/**
 * Generate random integer in range [min, max)
 */
export function generateRandomInt(min: number, max: number): number {
  return randomInt(min, max);
}

/**
 * Generate random alphanumeric string
 */
export function generateRandomAlphanumeric(length: number): string {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';

  for (let i = 0; i < length; i++) {
    result += chars[randomInt(0, chars.length)];
  }

  return result;
}

/**
 * Generate random UUID v4
 */
export function generateUUID(): string {
  const bytes = randomBytes(16);

  // Set version (4) and variant bits
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;

  const hex = bytes.toString('hex');

  return [
    hex.substring(0, 8),
    hex.substring(8, 12),
    hex.substring(12, 16),
    hex.substring(16, 20),
    hex.substring(20, 32),
  ].join('-');
}

/**
 * Generate random secure token
 */
export function generateSecureToken(
  options: {
    length?: number;
    encoding?: 'hex' | 'base64' | 'base64url' | 'alphanumeric';
  } = {}
): string {
  const { length = 32, encoding = 'base64url' } = options;

  if (encoding === 'alphanumeric') {
    return generateRandomAlphanumeric(length);
  }

  return generateRandomString(
    length,
    encoding as 'hex' | 'base64' | 'base64url'
  );
}
