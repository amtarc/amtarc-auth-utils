/**
 * Double-submit cookie CSRF protection pattern
 *
 * This pattern stores the CSRF token in a cookie and requires
 * the same token to be submitted in the request (header or body).
 * No server-side storage needed.
 */

import { generateCSRFToken, hashCSRFToken } from './generate-token';
import crypto from 'crypto';

export interface DoubleSubmitOptions {
  /** Cookie name for CSRF token (default: '__Host-csrf') */
  cookieName?: string;
  /** Header name for CSRF token (default: 'x-csrf-token') */
  headerName?: string;
  /** Form field name for CSRF token (default: '_csrf') */
  fieldName?: string;
  /** Cookie options */
  cookieOptions?: {
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    httpOnly?: boolean;
    path?: string;
    domain?: string;
  };
  /** Use hashed tokens for additional security */
  useHash?: boolean;
}

export interface DoubleSubmitResult {
  token: string;
  cookie: string;
}

/**
 * Generate CSRF token for double-submit pattern
 */
export function generateDoubleSubmitToken(
  options: DoubleSubmitOptions = {}
): DoubleSubmitResult {
  const {
    cookieName = '__Host-csrf',
    cookieOptions = {},
    useHash = true,
  } = options;

  // Generate random token
  const rawToken = generateCSRFToken({ length: 32 });
  const token = useHash ? hashCSRFToken(rawToken) : rawToken;

  // Create cookie
  const defaultCookieOptions = {
    secure: true,
    sameSite: 'strict' as const,
    httpOnly: true,
    path: '/',
    ...cookieOptions,
  };

  const cookieParts = [
    `${cookieName}=${token}`,
    defaultCookieOptions.secure && 'Secure',
    defaultCookieOptions.httpOnly && 'HttpOnly',
    `SameSite=${defaultCookieOptions.sameSite}`,
    defaultCookieOptions.path && `Path=${defaultCookieOptions.path}`,
    defaultCookieOptions.domain && `Domain=${defaultCookieOptions.domain}`,
  ].filter(Boolean);

  const cookie = cookieParts.join('; ');

  return { token, cookie };
}

/**
 * Validate double-submit CSRF token
 */
export function validateDoubleSubmitToken(
  cookieToken: string,
  submittedToken: string,
  options: { useHash?: boolean; strict?: boolean } = {}
): { valid: boolean; reason?: string } {
  const { useHash = true, strict = false } = options;

  // Check if tokens exist
  if (!cookieToken || !submittedToken) {
    if (strict) {
      throw new Error('CSRF token missing');
    }
    return { valid: false, reason: 'missing' };
  }

  // Process tokens based on hash usage
  const processedCookieToken = useHash
    ? hashCSRFToken(cookieToken)
    : cookieToken;
  const processedSubmittedToken = useHash
    ? hashCSRFToken(submittedToken)
    : submittedToken;

  // Constant-time comparison
  try {
    const isValid = crypto.timingSafeEqual(
      Buffer.from(processedCookieToken),
      Buffer.from(processedSubmittedToken)
    );

    if (!isValid) {
      if (strict) {
        throw new Error('CSRF token mismatch');
      }
      return { valid: false, reason: 'mismatch' };
    }

    return { valid: true };
  } catch (error) {
    if (strict) {
      throw error;
    }
    return { valid: false, reason: 'invalid' };
  }
}

/**
 * Extract CSRF token from request
 */
export function extractCSRFToken(
  request: {
    headers?: Record<string, string | string[] | undefined>;
    body?: Record<string, unknown>;
    cookies?: Record<string, string>;
  },
  options: DoubleSubmitOptions = {}
): { cookieToken?: string; submittedToken?: string } {
  const {
    cookieName = '__Host-csrf',
    headerName = 'x-csrf-token',
    fieldName = '_csrf',
  } = options;

  // Get cookie token
  const cookieToken = request.cookies?.[cookieName];

  // Get submitted token (check header first, then form field)
  const headerToken = request.headers?.[headerName];
  const bodyToken = request.body?.[fieldName];

  const submittedToken =
    (Array.isArray(headerToken) ? headerToken[0] : headerToken) ||
    (typeof bodyToken === 'string' ? bodyToken : undefined);

  const result: { cookieToken?: string; submittedToken?: string } = {};
  if (cookieToken) result.cookieToken = cookieToken;
  if (submittedToken) result.submittedToken = submittedToken;

  return result;
}
