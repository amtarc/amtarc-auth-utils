/**
 * Base error class for all auth-utils errors
 *
 * Provides consistent error structure with HTTP status codes,
 * operational error classification, and JSON serialization
 */
export class AuthUtilsError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly timestamp: Date;

  constructor(
    message: string,
    code: string,
    statusCode: number = 500,
    isOperational: boolean = true
  ) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.timestamp = new Date();

    Error.captureStackTrace(this, this.constructor);
    Object.setPrototypeOf(this, AuthUtilsError.prototype);
  }

  toJSON() {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      statusCode: this.statusCode,
      timestamp: this.timestamp,
    };
  }
}

/**
 * @deprecated Use AuthUtilsError instead
 * Base authentication error (kept for backwards compatibility)
 */
export class AuthError extends AuthUtilsError {
  constructor(message: string, code: string) {
    super(message, code, 500);
    this.name = 'AuthError';
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}
