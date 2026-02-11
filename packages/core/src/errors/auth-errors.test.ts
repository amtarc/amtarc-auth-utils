/**
 * @amtarc/auth-utils - Authentication & Authorization Error Tests
 */

import { describe, it, expect } from 'vitest';
import {
  UnauthenticatedError,
  UnauthorizedError,
  AlreadyAuthenticatedError,
  AuthenticationError,
  AuthorizationError,
  InvalidTokenError,
  RateLimitError,
  CSRFError,
  FingerprintMismatchError,
  InvalidRedirectError,
} from './auth-errors';
import { AuthUtilsError } from './base-errors';

describe('UnauthenticatedError', () => {
  it('should create error with default message', () => {
    const error = new UnauthenticatedError();

    expect(error.message).toBe('Authentication required');
    expect(error.code).toBe('UNAUTHENTICATED');
    expect(error.statusCode).toBe(401);
    expect(error.name).toBe('UnauthenticatedError');
  });

  it('should create error with custom message', () => {
    const error = new UnauthenticatedError('Please log in');

    expect(error.message).toBe('Please log in');
  });

  it('should extend AuthUtilsError', () => {
    const error = new UnauthenticatedError();

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(UnauthenticatedError);
  });
});

describe('UnauthorizedError', () => {
  it('should create error with default message', () => {
    const error = new UnauthorizedError();

    expect(error.message).toBe('Insufficient permissions');
    expect(error.code).toBe('UNAUTHORIZED');
    expect(error.statusCode).toBe(403);
    expect(error.name).toBe('UnauthorizedError');
  });

  it('should create error with custom message', () => {
    const error = new UnauthorizedError('Admin access required');

    expect(error.message).toBe('Admin access required');
  });
});

describe('AlreadyAuthenticatedError', () => {
  it('should create error with default message', () => {
    const error = new AlreadyAuthenticatedError();

    expect(error.message).toBe('Already authenticated');
    expect(error.code).toBe('ALREADY_AUTHENTICATED');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('AlreadyAuthenticatedError');
  });

  it('should create error with custom message', () => {
    const error = new AlreadyAuthenticatedError('You are logged in');

    expect(error.message).toBe('You are logged in');
  });
});

describe('AuthenticationError', () => {
  it('should create error with default message', () => {
    const error = new AuthenticationError();

    expect(error.message).toBe('Authentication failed');
    expect(error.code).toBe('AUTHENTICATION_ERROR');
    expect(error.statusCode).toBe(401);
    expect(error.name).toBe('AuthenticationError');
  });

  it('should create error with custom message', () => {
    const error = new AuthenticationError('Invalid credentials');

    expect(error.message).toBe('Invalid credentials');
  });
});

describe('AuthorizationError', () => {
  it('should create error with default message', () => {
    const error = new AuthorizationError();

    expect(error.message).toBe('Authorization failed');
    expect(error.code).toBe('AUTHORIZATION_ERROR');
    expect(error.statusCode).toBe(403);
    expect(error.name).toBe('AuthorizationError');
  });
});

describe('InvalidTokenError', () => {
  it('should create error with default message', () => {
    const error = new InvalidTokenError();

    expect(error.message).toBe('Invalid token');
    expect(error.code).toBe('INVALID_TOKEN');
    expect(error.statusCode).toBe(401);
    expect(error.name).toBe('InvalidTokenError');
  });

  it('should create error with custom message', () => {
    const error = new InvalidTokenError('Token expired');

    expect(error.message).toBe('Token expired');
  });
});

describe('RateLimitError', () => {
  it('should create error with default message', () => {
    const error = new RateLimitError();

    expect(error.message).toBe('Rate limit exceeded');
    expect(error.code).toBe('RATE_LIMIT_EXCEEDED');
    expect(error.statusCode).toBe(429);
    expect(error.name).toBe('RateLimitError');
  });

  it('should use 429 status code', () => {
    const error = new RateLimitError();

    expect(error.statusCode).toBe(429);
  });
});

describe('CSRFError', () => {
  it('should create error with default message', () => {
    const error = new CSRFError();

    expect(error.message).toBe('CSRF validation failed');
    expect(error.code).toBe('CSRF_ERROR');
    expect(error.statusCode).toBe(403);
    expect(error.name).toBe('CSRFError');
  });
});

describe('FingerprintMismatchError', () => {
  it('should create error with default message', () => {
    const error = new FingerprintMismatchError();

    expect(error.message).toBe('Session fingerprint mismatch');
    expect(error.code).toBe('FINGERPRINT_MISMATCH');
    expect(error.statusCode).toBe(401);
    expect(error.name).toBe('FingerprintMismatchError');
  });

  it('should create error with custom message', () => {
    const error = new FingerprintMismatchError('Device changed');

    expect(error.message).toBe('Device changed');
  });
});

describe('InvalidRedirectError', () => {
  it('should create error with default message', () => {
    const error = new InvalidRedirectError();

    expect(error.message).toBe('Invalid redirect URL');
    expect(error.code).toBe('INVALID_REDIRECT');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('InvalidRedirectError');
  });

  it('should create error with custom message', () => {
    const error = new InvalidRedirectError('Redirect not allowed');

    expect(error.message).toBe('Redirect not allowed');
  });
});

describe('Error JSON serialization', () => {
  it('should serialize all errors correctly', () => {
    const errors = [
      new UnauthenticatedError(),
      new UnauthorizedError(),
      new AlreadyAuthenticatedError(),
      new AuthenticationError(),
      new AuthorizationError(),
      new InvalidTokenError(),
      new RateLimitError(),
      new CSRFError(),
      new FingerprintMismatchError(),
      new InvalidRedirectError(),
    ];

    errors.forEach((error) => {
      const json = error.toJSON();
      expect(json).toHaveProperty('name');
      expect(json).toHaveProperty('message');
      expect(json).toHaveProperty('code');
      expect(json).toHaveProperty('statusCode');
      expect(json).toHaveProperty('timestamp');
    });
  });
});
