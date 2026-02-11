/**
 * Session management utilities
 *
 * @module session
 */

// Core session functions
export { createSession } from './create-session';
export { validateSession } from './validate-session';
export { requireSession } from './require-session';

// Session lifecycle
export {
  refreshSession,
  rotateSessionId,
  generateSessionId,
  type RefreshSessionOptions,
} from './refresh-session';

export {
  invalidateSession,
  invalidateUserSessions,
  invalidateAllSessions,
  type InvalidateOptions,
  type InvalidateUserSessionsOptions,
} from './invalidate-session';

// Session security
export {
  generateSessionFingerprint,
  validateFingerprint,
  compareFingerprints,
  extractFingerprintMetadata,
  type FingerprintMetadata,
  type FingerprintValidationOptions,
} from './fingerprint';

// Multi-device management
export {
  listUserSessions,
  revokeDeviceSession,
  enforceConcurrentSessionLimit,
  countUserSessions,
  findSessionByDevice,
  type SessionInfo,
  type ListUserSessionsOptions,
} from './multi-device';

// Storage adapters
export * from './storage';

// Re-export types
export type { Session, SessionOptions } from '../types';
