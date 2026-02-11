/**
 * @amtarc/auth-utils - Authentication & Authorization Errors
 * Specific error classes for auth-related failures
 */

import { AuthUtilsError } from './base-errors';

/**
 * User is not authenticated (needs to log in)
 * HTTP 401 Unauthorized
 */
export class UnauthenticatedError extends AuthUtilsError {
  constructor(message: string = 'Authentication required') {
    super(message, 'UNAUTHENTICATED', 401);
    this.name = 'UnauthenticatedError';
    Object.setPrototypeOf(this, UnauthenticatedError.prototype);
  }
}

/**
 * User is authenticated but lacks permissions
 * HTTP 403 Forbidden
 */
export class UnauthorizedError extends AuthUtilsError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 'UNAUTHORIZED', 403);
    this.name = 'UnauthorizedError';
    Object.setPrototypeOf(this, UnauthorizedError.prototype);
  }
}

/**
 * User is already authenticated (e.g., trying to access login page while logged in)
 * HTTP 400 Bad Request
 */
export class AlreadyAuthenticatedError extends AuthUtilsError {
  constructor(message: string = 'Already authenticated') {
    super(message, 'ALREADY_AUTHENTICATED', 400);
    this.name = 'AlreadyAuthenticatedError';
    Object.setPrototypeOf(this, AlreadyAuthenticatedError.prototype);
  }
}

/**
 * Authentication failed (wrong credentials, invalid token, etc.)
 * HTTP 401 Unauthorized
 */
export class AuthenticationError extends AuthUtilsError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTHENTICATION_ERROR', 401);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Authorization failed (user lacks required permissions)
 * HTTP 403 Forbidden
 */
export class AuthorizationError extends AuthUtilsError {
  constructor(message: string = 'Authorization failed') {
    super(message, 'AUTHORIZATION_ERROR', 403);
    this.name = 'AuthorizationError';
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

/**
 * Invalid token error (malformed, expired, revoked)
 * HTTP 401 Unauthorized
 */
export class InvalidTokenError extends AuthUtilsError {
  constructor(message: string = 'Invalid token') {
    super(message, 'INVALID_TOKEN', 401);
    this.name = 'InvalidTokenError';
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
  }
}

/**
 * Rate limit exceeded error
 * HTTP 429 Too Many Requests
 */
export class RateLimitError extends AuthUtilsError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 'RATE_LIMIT_EXCEEDED', 429);
    this.name = 'RateLimitError';
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

/**
 * CSRF validation failed error
 * HTTP 403 Forbidden
 */
export class CSRFError extends AuthUtilsError {
  constructor(message: string = 'CSRF validation failed') {
    super(message, 'CSRF_ERROR', 403);
    this.name = 'CSRFError';
    Object.setPrototypeOf(this, CSRFError.prototype);
  }
}

/**
 * Session fingerprint mismatch (potential session hijacking)
 * HTTP 401 Unauthorized
 */
export class FingerprintMismatchError extends AuthUtilsError {
  constructor(message: string = 'Session fingerprint mismatch') {
    super(message, 'FINGERPRINT_MISMATCH', 401);
    this.name = 'FingerprintMismatchError';
    Object.setPrototypeOf(this, FingerprintMismatchError.prototype);
  }
}

/**
 * Invalid redirect URL error (potential open redirect)
 * HTTP 400 Bad Request
 */
export class InvalidRedirectError extends AuthUtilsError {
  constructor(message: string = 'Invalid redirect URL') {
    super(message, 'INVALID_REDIRECT', 400);
    this.name = 'InvalidRedirectError';
    Object.setPrototypeOf(this, InvalidRedirectError.prototype);
  }
}
