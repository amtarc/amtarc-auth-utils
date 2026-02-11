/**
 * @amtarc/auth-utils - Error Type Guards
 * Type guards and utility functions for error handling
 */

import { AuthUtilsError } from './base-errors';
import {
  SessionNotFoundError,
  SessionExpiredError,
  InvalidSessionError,
  UnauthorizedSessionAccessError,
} from './session-errors';
import {
  UnauthenticatedError,
  AuthenticationError,
  AuthorizationError,
} from './auth-errors';
import { ValidationError } from './validation-errors';

/**
 * Check if error is an AuthUtilsError
 */
export function isAuthUtilsError(error: unknown): error is AuthUtilsError {
  return error instanceof AuthUtilsError;
}

/**
 * Check if error is operational (expected) vs programmer error
 *
 * Operational errors are expected errors that are part of normal flow
 * (e.g., validation errors, authentication failures).
 * Programmer errors are bugs in the code.
 */
export function isOperationalError(error: unknown): boolean {
  if (isAuthUtilsError(error)) {
    return error.isOperational;
  }
  return false;
}

/**
 * Type guard for session-related errors
 */
export function isSessionError(
  error: unknown
): error is
  | SessionNotFoundError
  | SessionExpiredError
  | InvalidSessionError
  | UnauthorizedSessionAccessError {
  return (
    error instanceof SessionNotFoundError ||
    error instanceof SessionExpiredError ||
    error instanceof InvalidSessionError ||
    error instanceof UnauthorizedSessionAccessError
  );
}

/**
 * Type guard for authentication-related errors
 */
export function isAuthenticationError(
  error: unknown
): error is UnauthenticatedError | AuthenticationError {
  return (
    error instanceof UnauthenticatedError ||
    error instanceof AuthenticationError
  );
}

/**
 * Type guard for authorization-related errors
 */
export function isAuthorizationError(
  error: unknown
): error is AuthorizationError {
  return error instanceof AuthorizationError;
}

/**
 * Type guard for validation errors
 */
export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}

/**
 * Get HTTP status code from error
 * Returns 500 for non-AuthUtilsError instances
 */
export function getErrorStatusCode(error: unknown): number {
  if (isAuthUtilsError(error)) {
    return error.statusCode;
  }
  return 500;
}

/**
 * Get error code from error
 * Returns 'INTERNAL_ERROR' for non-AuthUtilsError instances
 */
export function getErrorCode(error: unknown): string {
  if (isAuthUtilsError(error)) {
    return error.code;
  }
  return 'INTERNAL_ERROR';
}

/**
 * Convert error to JSON-serializable object
 * Safe for sending in HTTP responses
 */
export function serializeError(error: unknown): {
  name: string;
  message: string;
  code: string;
  statusCode: number;
  timestamp?: Date;
  [key: string]: unknown;
} {
  if (isAuthUtilsError(error)) {
    return error.toJSON();
  }

  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      code: 'INTERNAL_ERROR',
      statusCode: 500,
    };
  }

  return {
    name: 'Error',
    message: String(error),
    code: 'UNKNOWN_ERROR',
    statusCode: 500,
  };
}
