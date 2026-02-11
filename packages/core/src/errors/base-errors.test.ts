/**
 * @amtarc/auth-utils - Base Error Tests
 */

import { describe, it, expect } from 'vitest';
import { AuthUtilsError, AuthError } from './base-errors';

describe('AuthUtilsError', () => {
  describe('constructor', () => {
    it('should create error with all properties', () => {
      const error = new AuthUtilsError('Test error', 'TEST_CODE', 400, true);

      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.statusCode).toBe(400);
      expect(error.isOperational).toBe(true);
      expect(error.name).toBe('AuthUtilsError');
      expect(error.timestamp).toBeInstanceOf(Date);
    });

    it('should use default statusCode if not provided', () => {
      const error = new AuthUtilsError('Test', 'CODE');

      expect(error.statusCode).toBe(500);
    });

    it('should use default isOperational if not provided', () => {
      const error = new AuthUtilsError('Test', 'CODE', 400);

      expect(error.isOperational).toBe(true);
    });

    it('should be instance of Error', () => {
      const error = new AuthUtilsError('Test', 'CODE');

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(AuthUtilsError);
    });
  });

  describe('toJSON', () => {
    it('should serialize to JSON correctly', () => {
      const error = new AuthUtilsError('Test error', 'TEST_CODE', 400);
      const json = error.toJSON();

      expect(json).toHaveProperty('name', 'AuthUtilsError');
      expect(json).toHaveProperty('message', 'Test error');
      expect(json).toHaveProperty('code', 'TEST_CODE');
      expect(json).toHaveProperty('statusCode', 400);
      expect(json).toHaveProperty('timestamp');
      expect(json.timestamp).toBeInstanceOf(Date);
    });

    it('should not include stack trace in JSON', () => {
      const error = new AuthUtilsError('Test', 'CODE');
      const json = error.toJSON();

      expect(json).not.toHaveProperty('stack');
    });
  });

  describe('stack trace', () => {
    it('should have stack trace', () => {
      const error = new AuthUtilsError('Test', 'CODE');

      expect(error.stack).toBeDefined();
      expect(error.stack).toContain('AuthUtilsError');
    });
  });

  describe('inheritance', () => {
    it('should allow instanceof checks', () => {
      const error = new AuthUtilsError('Test', 'CODE');

      expect(error instanceof AuthUtilsError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });

    it('should work with subclasses', () => {
      class CustomError extends AuthUtilsError {
        constructor() {
          super('Custom', 'CUSTOM', 400);
          Object.setPrototypeOf(this, CustomError.prototype);
        }
      }

      const error = new CustomError();

      expect(error instanceof CustomError).toBe(true);
      expect(error instanceof AuthUtilsError).toBe(true);
      expect(error instanceof Error).toBe(true);
    });
  });
});

describe('AuthError (deprecated)', () => {
  it('should create error with backwards compatibility', () => {
    const error = new AuthError('Test error', 'TEST_CODE');

    expect(error.message).toBe('Test error');
    expect(error.code).toBe('TEST_CODE');
    expect(error.statusCode).toBe(500);
    expect(error.name).toBe('AuthError');
  });

  it('should extend AuthUtilsError', () => {
    const error = new AuthError('Test', 'CODE');

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(AuthError);
  });
});
