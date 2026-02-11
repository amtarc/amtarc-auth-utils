/**
 * @amtarc/auth-utils - Error Type Guards Tests
 */

import { describe, it, expect } from 'vitest';
import {
  isAuthUtilsError,
  isOperationalError,
  isSessionError,
  isAuthenticationError,
  isAuthorizationError,
  isValidationError,
  getErrorStatusCode,
  getErrorCode,
  serializeError,
} from './type-guards';
import { AuthUtilsError } from './base-errors';
import {
  UnauthenticatedError,
  AuthenticationError,
  AuthorizationError,
} from './auth-errors';
import {
  SessionNotFoundError,
  SessionExpiredError,
  InvalidSessionError,
  UnauthorizedSessionAccessError,
} from './session-errors';
import { ValidationError } from './validation-errors';

describe('isAuthUtilsError', () => {
  it('should return true for AuthUtilsError instances', () => {
    const error = new AuthUtilsError('Test', 'CODE');

    expect(isAuthUtilsError(error)).toBe(true);
  });

  it('should return true for subclasses', () => {
    const errors = [
      new UnauthenticatedError(),
      new SessionExpiredError(),
      new ValidationError('Test'),
    ];

    errors.forEach((error) => {
      expect(isAuthUtilsError(error)).toBe(true);
    });
  });

  it('should return false for regular errors', () => {
    const error = new Error('Test');

    expect(isAuthUtilsError(error)).toBe(false);
  });

  it('should return false for non-errors', () => {
    expect(isAuthUtilsError(null)).toBe(false);
    expect(isAuthUtilsError(undefined)).toBe(false);
    expect(isAuthUtilsError('error')).toBe(false);
    expect(isAuthUtilsError({})).toBe(false);
    expect(isAuthUtilsError(123)).toBe(false);
  });
});

describe('isOperationalError', () => {
  it('should return true for operational errors', () => {
    const error = new AuthUtilsError('Test', 'CODE', 400, true);

    expect(isOperationalError(error)).toBe(true);
  });

  it('should return false for non-operational errors', () => {
    const error = new AuthUtilsError('Test', 'CODE', 500, false);

    expect(isOperationalError(error)).toBe(false);
  });

  it('should return false for regular errors', () => {
    const error = new Error('Test');

    expect(isOperationalError(error)).toBe(false);
  });

  it('should return false for non-errors', () => {
    expect(isOperationalError(null)).toBe(false);
    expect(isOperationalError(undefined)).toBe(false);
  });
});

describe('isSessionError', () => {
  it('should return true for session errors', () => {
    const errors = [
      new SessionNotFoundError(),
      new SessionExpiredError(),
      new InvalidSessionError(),
      new UnauthorizedSessionAccessError(),
    ];

    errors.forEach((error) => {
      expect(isSessionError(error)).toBe(true);
    });
  });

  it('should return false for non-session errors', () => {
    const errors = [
      new UnauthenticatedError(),
      new ValidationError('Test'),
      new Error('Test'),
    ];

    errors.forEach((error) => {
      expect(isSessionError(error)).toBe(false);
    });
  });

  it('should return false for non-errors', () => {
    expect(isSessionError(null)).toBe(false);
    expect(isSessionError({})).toBe(false);
  });
});

describe('isAuthenticationError', () => {
  it('should return true for authentication errors', () => {
    const errors = [new UnauthenticatedError(), new AuthenticationError()];

    errors.forEach((error) => {
      expect(isAuthenticationError(error)).toBe(true);
    });
  });

  it('should return false for other errors', () => {
    const errors = [
      new AuthorizationError(),
      new SessionExpiredError(),
      new Error('Test'),
    ];

    errors.forEach((error) => {
      expect(isAuthenticationError(error)).toBe(false);
    });
  });
});

describe('isAuthorizationError', () => {
  it('should return true for authorization errors', () => {
    const error = new AuthorizationError();

    expect(isAuthorizationError(error)).toBe(true);
  });

  it('should return false for other errors', () => {
    const errors = [
      new UnauthenticatedError(),
      new SessionExpiredError(),
      new Error('Test'),
    ];

    errors.forEach((error) => {
      expect(isAuthorizationError(error)).toBe(false);
    });
  });
});

describe('isValidationError', () => {
  it('should return true for validation errors', () => {
    const error = new ValidationError('Test');

    expect(isValidationError(error)).toBe(true);
  });

  it('should return false for other errors', () => {
    const errors = [
      new UnauthenticatedError(),
      new SessionExpiredError(),
      new Error('Test'),
    ];

    errors.forEach((error) => {
      expect(isValidationError(error)).toBe(false);
    });
  });
});

describe('getErrorStatusCode', () => {
  it('should return status code for AuthUtilsError', () => {
    const error = new UnauthenticatedError();

    expect(getErrorStatusCode(error)).toBe(401);
  });

  it('should return 500 for non-AuthUtilsError', () => {
    const error = new Error('Test');

    expect(getErrorStatusCode(error)).toBe(500);
  });

  it('should return 500 for non-errors', () => {
    expect(getErrorStatusCode(null)).toBe(500);
    expect(getErrorStatusCode('error')).toBe(500);
    expect(getErrorStatusCode({})).toBe(500);
  });

  it('should return correct codes for different error types', () => {
    expect(getErrorStatusCode(new UnauthenticatedError())).toBe(401);
    expect(getErrorStatusCode(new AuthorizationError())).toBe(403);
    expect(getErrorStatusCode(new SessionNotFoundError())).toBe(404);
    expect(getErrorStatusCode(new ValidationError('Test'))).toBe(400);
  });
});

describe('getErrorCode', () => {
  it('should return error code for AuthUtilsError', () => {
    const error = new UnauthenticatedError();

    expect(getErrorCode(error)).toBe('UNAUTHENTICATED');
  });

  it('should return INTERNAL_ERROR for non-AuthUtilsError', () => {
    const error = new Error('Test');

    expect(getErrorCode(error)).toBe('INTERNAL_ERROR');
  });

  it('should return INTERNAL_ERROR for non-errors', () => {
    expect(getErrorCode(null)).toBe('INTERNAL_ERROR');
    expect(getErrorCode('error')).toBe('INTERNAL_ERROR');
  });

  it('should return correct codes for different error types', () => {
    expect(getErrorCode(new UnauthenticatedError())).toBe('UNAUTHENTICATED');
    expect(getErrorCode(new AuthorizationError())).toBe('AUTHORIZATION_ERROR');
    expect(getErrorCode(new SessionExpiredError())).toBe('SESSION_EXPIRED');
    expect(getErrorCode(new ValidationError('Test'))).toBe('VALIDATION_ERROR');
  });
});

describe('serializeError', () => {
  it('should serialize AuthUtilsError', () => {
    const error = new UnauthenticatedError('Please login');
    const serialized = serializeError(error);

    expect(serialized).toHaveProperty('name', 'UnauthenticatedError');
    expect(serialized).toHaveProperty('message', 'Please login');
    expect(serialized).toHaveProperty('code', 'UNAUTHENTICATED');
    expect(serialized).toHaveProperty('statusCode', 401);
    expect(serialized).toHaveProperty('timestamp');
  });

  it('should serialize regular Error', () => {
    const error = new Error('Test error');
    const serialized = serializeError(error);

    expect(serialized).toHaveProperty('name', 'Error');
    expect(serialized).toHaveProperty('message', 'Test error');
    expect(serialized).toHaveProperty('code', 'INTERNAL_ERROR');
    expect(serialized).toHaveProperty('statusCode', 500);
  });

  it('should serialize non-error values', () => {
    const serialized = serializeError('string error');

    expect(serialized).toHaveProperty('name', 'Error');
    expect(serialized).toHaveProperty('message', 'string error');
    expect(serialized).toHaveProperty('code', 'UNKNOWN_ERROR');
    expect(serialized).toHaveProperty('statusCode', 500);
  });

  it('should handle null and undefined', () => {
    expect(serializeError(null)).toHaveProperty('message', 'null');
    expect(serializeError(undefined)).toHaveProperty('message', 'undefined');
  });

  it('should serialize ValidationError with fields', () => {
    const fields = { email: ['Invalid email'] };
    const error = new ValidationError('Validation failed', fields);
    const serialized = serializeError(error);

    expect(serialized).toHaveProperty('fields', fields);
  });

  it('should serialize SessionNotFoundError with sessionId', () => {
    const error = new SessionNotFoundError('sess_123');
    const serialized = serializeError(error);

    expect(serialized).toHaveProperty('sessionId', 'sess_123');
  });

  it('should not include stack trace', () => {
    const error = new UnauthenticatedError();
    const serialized = serializeError(error);

    expect(serialized).not.toHaveProperty('stack');
  });
});
