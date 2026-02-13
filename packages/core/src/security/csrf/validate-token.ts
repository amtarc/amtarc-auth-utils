/**
 * CSRF token validation utilities
 */

import type { CSRFStorageAdapter } from './storage';
import { CSRFError } from '../../errors/auth-errors';
import crypto from 'crypto';

export interface ValidateCSRFTokenOptions {
  /** Storage adapter for token lookup */
  storage: CSRFStorageAdapter;
  /** Token key identifier */
  key: string;
  /** Whether to delete token after validation (one-time use) */
  deleteAfterUse?: boolean;
  /** Strict mode: throw on validation failure */
  strict?: boolean;
}

export interface CSRFValidationResult {
  valid: boolean;
  reason?: 'missing' | 'expired' | 'mismatch' | 'invalid';
  token?: string;
}

/**
 * Validate a CSRF token against stored value
 */
export async function validateCSRFToken(
  token: string,
  options: ValidateCSRFTokenOptions
): Promise<CSRFValidationResult> {
  const { storage, key, deleteAfterUse = false, strict = false } = options;

  // Check if token exists
  if (!token || typeof token !== 'string') {
    if (strict) {
      throw new CSRFError('CSRF token is required');
    }
    return { valid: false, reason: 'missing' };
  }

  // Get stored token
  const storedToken = await storage.get(key);

  if (!storedToken) {
    if (strict) {
      throw new CSRFError('CSRF token not found or expired');
    }
    return { valid: false, reason: 'expired' };
  }

  // Check if timestamped token (format: timestamp.expiresAt.token)
  if (token.includes('.') && token.split('.').length === 3) {
    const timestampResult = validateTimestampedToken(token);
    if (!timestampResult.valid) {
      if (strict) {
        throw new CSRFError(`CSRF token ${timestampResult.reason}`);
      }
      return timestampResult;
    }
    // Extract actual token from timestamped format
    const actualToken = token.split('.')[2] || '';
    const isValid = crypto.timingSafeEqual(
      Buffer.from(actualToken),
      Buffer.from(storedToken.split('.')[2] || '')
    );
    if (!isValid) {
      if (strict) {
        throw new CSRFError('CSRF token mismatch');
      }
      return { valid: false, reason: 'mismatch' };
    }
  } else {
    // Handle potential length difference
    if (token.length !== storedToken.length) {
      if (strict) {
        throw new CSRFError('CSRF token mismatch');
      }
      return { valid: false, reason: 'mismatch' };
    }

    // Constant-time comparison to prevent timing attacks
    const isValid = crypto.timingSafeEqual(
      Buffer.from(token),
      Buffer.from(storedToken)
    );

    if (!isValid) {
      if (strict) {
        throw new CSRFError('CSRF token mismatch');
      }
      return { valid: false, reason: 'mismatch' };
    }
  }

  // Delete token if one-time use
  if (deleteAfterUse) {
    await storage.delete(key);
  }

  return { valid: true, token };
}

/**
 * Validate timestamped CSRF token
 */
export function validateTimestampedToken(
  token: string,
  options: { maxAge?: number; strict?: boolean } = {}
): CSRFValidationResult {
  const { maxAge = 3600000, strict = false } = options;

  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid token format');
    }

    const [timestampStr, expiresAtStr] = parts;
    const timestamp = Number(timestampStr);
    const expiresAt = Number(expiresAtStr);
    const now = Date.now();

    // Check if expired
    if (now > expiresAt) {
      if (strict) {
        throw new CSRFError('CSRF token has expired');
      }
      return { valid: false, reason: 'expired' };
    }

    // Check age limit
    const age = now - timestamp;
    if (age > maxAge) {
      if (strict) {
        throw new CSRFError('CSRF token is too old');
      }
      return { valid: false, reason: 'expired' };
    }

    return { valid: true, token };
  } catch (error) {
    if (strict) {
      throw new CSRFError('Invalid CSRF token format');
    }
    return { valid: false, reason: 'invalid' };
  }
}
