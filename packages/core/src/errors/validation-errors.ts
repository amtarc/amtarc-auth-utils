/**
 * @amtarc/auth-utils - Validation Errors
 * Errors for input validation failures
 */

import { AuthUtilsError } from './base-errors';

/**
 * Validation error with optional field-level error details
 * HTTP 400 Bad Request
 */
export class ValidationError extends AuthUtilsError {
  public readonly fields?: Record<string, string[]>;

  constructor(message: string, fields?: Record<string, string[]>) {
    super(message, 'VALIDATION_ERROR', 400);
    this.name = 'ValidationError';
    if (fields !== undefined) {
      this.fields = fields;
    }
    Object.setPrototypeOf(this, ValidationError.prototype);
  }

  override toJSON() {
    return {
      ...super.toJSON(),
      ...(this.fields !== undefined && { fields: this.fields }),
    };
  }
}

/**
 * Invalid input error (generic validation failure)
 * HTTP 400 Bad Request
 */
export class InvalidInputError extends AuthUtilsError {
  constructor(message: string = 'Invalid input') {
    super(message, 'INVALID_INPUT', 400);
    this.name = 'InvalidInputError';
    Object.setPrototypeOf(this, InvalidInputError.prototype);
  }
}

/**
 * Missing required field error
 * HTTP 400 Bad Request
 */
export class MissingFieldError extends AuthUtilsError {
  public readonly field: string;

  constructor(field: string, message?: string) {
    super(message || `Missing required field: ${field}`, 'MISSING_FIELD', 400);
    this.name = 'MissingFieldError';
    this.field = field;
    Object.setPrototypeOf(this, MissingFieldError.prototype);
  }

  override toJSON() {
    return {
      ...super.toJSON(),
      field: this.field,
    };
  }
}
