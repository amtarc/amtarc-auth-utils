import { AuthError } from './base-errors';

/**
 * Session expired error
 */
export class SessionExpiredError extends AuthError {
  constructor(message: string = 'Session expired') {
    super(message, 'SESSION_EXPIRED');
    this.name = 'SessionExpiredError';
    Object.setPrototypeOf(this, SessionExpiredError.prototype);
  }
}

/**
 * Invalid session error
 */
export class InvalidSessionError extends AuthError {
  constructor(message: string = 'Invalid session') {
    super(message, 'INVALID_SESSION');
    this.name = 'InvalidSessionError';
    Object.setPrototypeOf(this, InvalidSessionError.prototype);
  }
}
