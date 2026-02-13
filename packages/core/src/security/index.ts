/**
 * Security Package
 * Comprehensive security utilities for authentication
 *
 * @module @auth-utils/core/security
 */

export * from './csrf';
export * from './rate-limit';
export * from './headers';
export * from './encryption';

// Convenience exports for common use cases
export {
  // CSRF Protection
  generateCSRFToken,
  validateCSRFToken,
  generateDoubleSubmitToken,
  validateDoubleSubmitToken,
  generateSynchronizerToken,
  validateSynchronizerToken,
  MemoryCSRFStorage,
  SessionCSRFStorage,
  SessionCSRFAdapter,
  CSRFError,
} from './csrf';

export {
  // Rate Limiting
  createRateLimiter,
  checkRateLimit,
  BruteForceProtection,
  MemoryRateLimitStorage,
} from './rate-limit';

export {
  // Security Headers
  CSPBuilder,
  SecurityHeadersBuilder,
  createSecurityHeaders,
} from './headers';

export {
  // Encryption
  encrypt,
  decrypt,
  encryptToString,
  decryptFromString,
  deriveKey,
  deriveKeyPBKDF2,
  deriveKeyScrypt,
  generateSecureToken,
  generateRandomBytes,
  generateRandomString,
  generateUUID,
} from './encryption';
