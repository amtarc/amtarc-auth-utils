/**
 * @amtarc/auth-utils - Validation Error Tests
 */

import { describe, it, expect } from 'vitest';
import {
  ValidationError,
  InvalidInputError,
  MissingFieldError,
} from './validation-errors';
import { AuthUtilsError } from './base-errors';

describe('ValidationError', () => {
  it('should create error without fields', () => {
    const error = new ValidationError('Validation failed');

    expect(error.message).toBe('Validation failed');
    expect(error.code).toBe('VALIDATION_ERROR');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('ValidationError');
    expect(error.fields).toBeUndefined();
  });

  it('should create error with field details', () => {
    const fields = {
      email: ['Invalid email format', 'Email is required'],
      password: ['Password too short'],
    };
    const error = new ValidationError('Validation failed', fields);

    expect(error.message).toBe('Validation failed');
    expect(error.fields).toEqual(fields);
  });

  it('should include fields in JSON', () => {
    const fields = {
      username: ['Username already taken'],
    };
    const error = new ValidationError('Validation failed', fields);
    const json = error.toJSON();

    expect(json).toHaveProperty('fields', fields);
    expect(json).toHaveProperty('message', 'Validation failed');
    expect(json).toHaveProperty('code', 'VALIDATION_ERROR');
  });

  it('should handle empty fields object', () => {
    const error = new ValidationError('Validation failed', {});

    expect(error.fields).toEqual({});
  });

  it('should extend AuthUtilsError', () => {
    const error = new ValidationError('Test');

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(ValidationError);
  });
});

describe('InvalidInputError', () => {
  it('should create error with default message', () => {
    const error = new InvalidInputError();

    expect(error.message).toBe('Invalid input');
    expect(error.code).toBe('INVALID_INPUT');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('InvalidInputError');
  });

  it('should create error with custom message', () => {
    const error = new InvalidInputError('Invalid date format');

    expect(error.message).toBe('Invalid date format');
  });

  it('should extend AuthUtilsError', () => {
    const error = new InvalidInputError();

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(InvalidInputError);
  });
});

describe('MissingFieldError', () => {
  it('should create error with field name', () => {
    const error = new MissingFieldError('email');

    expect(error.message).toBe('Missing required field: email');
    expect(error.code).toBe('MISSING_FIELD');
    expect(error.statusCode).toBe(400);
    expect(error.name).toBe('MissingFieldError');
    expect(error.field).toBe('email');
  });

  it('should create error with custom message', () => {
    const error = new MissingFieldError('password', 'Password is required');

    expect(error.message).toBe('Password is required');
    expect(error.field).toBe('password');
  });

  it('should include field in JSON', () => {
    const error = new MissingFieldError('username');
    const json = error.toJSON();

    expect(json).toHaveProperty('field', 'username');
    expect(json).toHaveProperty('message', 'Missing required field: username');
  });

  it('should extend AuthUtilsError', () => {
    const error = new MissingFieldError('test');

    expect(error).toBeInstanceOf(AuthUtilsError);
    expect(error).toBeInstanceOf(MissingFieldError);
  });
});

describe('Validation errors JSON serialization', () => {
  it('should serialize all validation errors correctly', () => {
    const errors = [
      new ValidationError('Test'),
      new ValidationError('Test', { email: ['Invalid'] }),
      new InvalidInputError(),
      new MissingFieldError('email'),
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
