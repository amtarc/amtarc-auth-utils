/**
 * @amtarc/auth-utils - Session Error Tests
 */

import { describe, it, expect } from 'vitest';
import {
  SessionNotFoundError,
  SessionExpiredError,
  InvalidSessionError,
  UnauthorizedSessionAccessError,
} from './session-errors';
import { AuthUtilsError } from './base-errors';

describe('SessionNotFoundError', () => {
  it('should create error without session ID', () => {
    const error = new SessionNotFoundError();

    expect(error.message).toBe('Session not found');
    expect(error.code).toBe('SESSION_NOT_FOUND');
    expect(error.statusCode).toBe(404);
    expect(error.name).toBe('SessionNotFoundError');
    expect(error.sessionId).toBeUndefined();
  });

  it('should create error with session ID', () => {
    const error = new SessionNotFoundError('sess_123');

    expect(error.message).toBe('Session sess_123 not found');
    expect(error.sessionId).toBe('sess_123');
  });

  it('should include sessionId in JSON', () => {
    const error = new SessionNotFoundError('sess_456');
    const json = error.toJSON();

    expect(json).toHaveProperty('sessionId', 'sess_456');
    expect(json).toHaveProperty('message', 'Session sess_456 not found');
  });

  it('should extend AuthUtilsError', () => {
    const error = new SessionNotFoundError();

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(SessionNotFoundError);
  });
});

describe('SessionExpiredError', () => {
  it('should create error with default message', () => {
    const error = new SessionExpiredError();

    expect(error.message).toBe('Session has expired');
    expect(error.code).toBe('SESSION_EXPIRED');
    expect(error.statusCode).toBe(401);
    expect(error.name).toBe('SessionExpiredError');
  });

  it('should create error with custom message', () => {
    const error = new SessionExpiredError('Your session timed out');

    expect(error.message).toBe('Your session timed out');
    expect(error.code).toBe('SESSION_EXPIRED');
  });

  it('should extend AuthUtilsError', () => {
    const error = new SessionExpiredError();

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(SessionExpiredError);
  });
});

describe('InvalidSessionError', () => {
  it('should create error with default message', () => {
    const error = new InvalidSessionError();

    expect(error.message).toBe('Session is invalid');
    expect(error.code).toBe('SESSION_INVALID');
    expect(error.statusCode).toBe(401);
    expect(error.name).toBe('InvalidSessionError');
  });

  it('should create error with custom message', () => {
    const error = new InvalidSessionError('Session data corrupted');

    expect(error.message).toBe('Session data corrupted');
  });

  it('should extend AuthUtilsError', () => {
    const error = new InvalidSessionError();

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(InvalidSessionError);
  });
});

describe('UnauthorizedSessionAccessError', () => {
  it('should create error with default message', () => {
    const error = new UnauthorizedSessionAccessError();

    expect(error.message).toBe('Unauthorized session access');
    expect(error.code).toBe('UNAUTHORIZED_SESSION_ACCESS');
    expect(error.statusCode).toBe(403);
    expect(error.name).toBe('UnauthorizedSessionAccessError');
  });

  it('should create error with custom message', () => {
    const error = new UnauthorizedSessionAccessError(
      'Cannot access this session'
    );

    expect(error.message).toBe('Cannot access this session');
  });

  it('should use 403 status code', () => {
    const error = new UnauthorizedSessionAccessError();

    expect(error.statusCode).toBe(403);
  });

  it('should extend AuthUtilsError', () => {
    const error = new UnauthorizedSessionAccessError();

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(UnauthorizedSessionAccessError);
  });
});

describe('Session errors JSON serialization', () => {
  it('should serialize all session errors correctly', () => {
    const errors = [
      new SessionNotFoundError(),
      new SessionNotFoundError('sess_123'),
      new SessionExpiredError(),
      new InvalidSessionError(),
      new UnauthorizedSessionAccessError(),
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
