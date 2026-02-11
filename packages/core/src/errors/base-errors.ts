/**
 * Base authentication error
 */
export class AuthError extends Error {
  public readonly code: string;

  constructor(message: string, code: string) {
    super(message);
    this.name = 'AuthError';
    this.code = code;
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

/**
 * Authentication failed error
 */
export class AuthenticationError extends AuthError {
  constructor(message: string = 'Authentication failed') {
    super(message, 'AUTHENTICATION_ERROR');
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Authorization failed error
 */
export class AuthorizationError extends AuthError {
  constructor(message: string = 'Authorization failed') {
    super(message, 'AUTHORIZATION_ERROR');
    this.name = 'AuthorizationError';
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

/**
 * Invalid token error
 */
export class InvalidTokenError extends AuthError {
  constructor(message: string = 'Invalid token') {
    super(message, 'INVALID_TOKEN');
    this.name = 'InvalidTokenError';
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
  }
}

/**
 * Rate limit exceeded error
 */
export class RateLimitError extends AuthError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 'RATE_LIMIT_EXCEEDED');
    this.name = 'RateLimitError';
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

/**
 * CSRF validation failed error
 */
export class CSRFError extends AuthError {
  constructor(message: string = 'CSRF validation failed') {
    super(message, 'CSRF_ERROR');
    this.name = 'CSRFError';
    Object.setPrototypeOf(this, CSRFError.prototype);
  }
}
