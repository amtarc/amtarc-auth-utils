/**
 * @amtarc/auth-utils - Cookie Utilities
 * Secure cookie management for authentication
 */

// Re-export types
export type { CookieOptions } from '../types';

// Cookie creation and parsing
export {
  createAuthCookie,
  createAuthCookies,
  isValidCookieName,
  isValidCookieValue,
  estimateCookieSize,
} from './create-cookie';

export type { ParsedCookie } from './parse-cookie';
export {
  parseAuthCookies,
  getAuthCookie,
  hasAuthCookie,
  parseSetCookie,
} from './parse-cookie';

// Cookie signing (HMAC)
export {
  signCookie,
  unsignCookie,
  verifyCookieSignature,
  signAndCreateCookie,
  unsignCookieStrict,
  CookieSignatureError,
} from './sign-cookie';

// Cookie encryption (AES-256-GCM)
export {
  encryptCookie,
  decryptCookie,
  verifyEncryptedCookie,
  encryptAndCreateCookie,
  decryptCookieStrict,
  CookieDecryptionError,
} from './encrypt-cookie';

// Cookie deletion
export {
  deleteAuthCookie,
  deleteAuthCookies,
  deleteAuthCookieExact,
  deleteAuthCookieAllPaths,
} from './delete-cookie';

// Cookie rotation
export type { CookieRotationResult } from './rotate-cookie';
export {
  rotateCookie,
  rotateCookies,
  rotateSignedCookie,
  rotateEncryptedCookie,
  shouldRotateCookie,
} from './rotate-cookie';
