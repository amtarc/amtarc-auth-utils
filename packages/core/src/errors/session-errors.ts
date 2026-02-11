/**
 * @amtarc/auth-utils - Session Errors
 * Specific error classes for session-related failures
 */

import { AuthUtilsError } from './base-errors';

/**
 * Session not found error
 * HTTP 404 Not Found
 */
export class SessionNotFoundError extends AuthUtilsError {
  public readonly sessionId?: string;

  constructor(sessionId?: string) {
    const message = sessionId
      ? `Session ${sessionId} not found`
      : 'Session not found';
    super(message, 'SESSION_NOT_FOUND', 404);
    this.name = 'SessionNotFoundError';
    if (sessionId !== undefined) {
      this.sessionId = sessionId;
    }
    Object.setPrototypeOf(this, SessionNotFoundError.prototype);
  }

  override toJSON() {
    return {
      ...super.toJSON(),
      ...(this.sessionId !== undefined && { sessionId: this.sessionId }),
    };
  }
}

/**
 * Session expired error
 * HTTP 401 Unauthorized
 */
export class SessionExpiredError extends AuthUtilsError {
  constructor(message: string = 'Session has expired') {
    super(message, 'SESSION_EXPIRED', 401);
    this.name = 'SessionExpiredError';
    Object.setPrototypeOf(this, SessionExpiredError.prototype);
  }
}

/**
 * Invalid session error
 * HTTP 401 Unauthorized
 */
export class InvalidSessionError extends AuthUtilsError {
  constructor(message: string = 'Session is invalid') {
    super(message, 'SESSION_INVALID', 401);
    this.name = 'InvalidSessionError';
    Object.setPrototypeOf(this, InvalidSessionError.prototype);
  }
}

/**
 * Unauthorized session access error (e.g., accessing another user's session)
 * HTTP 403 Forbidden
 */
export class UnauthorizedSessionAccessError extends AuthUtilsError {
  constructor(message: string = 'Unauthorized session access') {
    super(message, 'UNAUTHORIZED_SESSION_ACCESS', 403);
    this.name = 'UnauthorizedSessionAccessError';
    Object.setPrototypeOf(this, UnauthorizedSessionAccessError.prototype);
  }
}
