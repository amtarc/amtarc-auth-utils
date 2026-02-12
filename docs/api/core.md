# @amtarc/auth-utils API Reference

Complete API reference for the core authentication utilities package.

## Installation

```bash
npm install @amtarc/auth-utils
```

## Import Paths

```typescript
// Main exports (all features)
import { createSession, requireAuth } from '@amtarc/auth-utils';

// Module-specific exports
import { 
  createSession,
  validateSession,
  refreshSession,
  invalidateSession
} from '@amtarc/auth-utils/session';

import { 
  requireAuth, 
  requireGuest, 
  requireAny 
} from '@amtarc/auth-utils/guards';

import { 
  createAuthCookie, 
  signCookie,
  encryptCookie 
} from '@amtarc/auth-utils/cookies';

import { 
  UnauthenticatedError,
  SessionExpiredError,
  isAuthUtilsError 
} from '@amtarc/auth-utils/errors';
```

---

## Session Management

### createSession

Create a new session for a user.

```typescript
function createSession<TUser extends User = User>(
  user: TUser,
  options?: SessionOptions
): Session<TUser>
```

**Parameters:**
- `user`: User object with at least an `id` property
- `options`: Session configuration options

**Options:**
```typescript
interface SessionOptions {
  expiresIn?: number;      // Session lifetime in milliseconds
  absoluteTimeout?: number; // Absolute max lifetime
  renewalTimeout?: number;  // Auto-renewal threshold
}
```

**Returns:** `Session<TUser>` object

**Example:**
```typescript
const session = createSession(
  { id: 'user-123', email: 'user@example.com' },
  { expiresIn: 1000 * 60 * 60 * 24 }
);
```

### validateSession

Validate a session's expiration and timeouts.

```typescript
function validateSession<TUser extends User = User>(
  session: Session<TUser>
): ValidationResult
```

**Returns:** 
```typescript
interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'absolute-timeout-exceeded';
  needsRenewal: boolean;
}
```

**Example:**
```typescript
const result = validateSession(session);
if (!result.valid) {
  throw new SessionExpiredError(result.reason);
}
```

### requireSession

Create a session-protected handler.

```typescript
function requireSession<TUser extends User = User, TResult = unknown>(
  getSession: () => Session<TUser> | null | Promise<Session<TUser> | null>,
  handler: SessionHandler<TUser, TResult>,
  options?: SessionOptions
): () => Promise<TResult>
```

**Type:**
```typescript
type SessionHandler<TUser extends User = User, TResult = unknown> = (
  session: Session<TUser>
) => TResult | Promise<TResult>;
```

**Example:**
```typescript
const protectedHandler = requireSession(
  () => getSessionFromRequest(req),
  async (session) => {
    return { userId: session.user.id };
  }
);
```

### refreshSession

Refresh a session, extending its expiration.

```typescript
function refreshSession<TUser extends User = User>(
  session: Session<TUser>,
  storage: SessionStorageAdapter<TUser>,
  options?: RefreshSessionOptions
): Promise<Session<TUser>>
```

**Options:**
```typescript
interface RefreshSessionOptions {
  rotateId?: boolean;    // Generate new session ID
  expiresIn?: number;    // New expiration time
}
```

**Example:**
```typescript
const refreshed = await refreshSession(session, storage, {
  rotateId: true,
  expiresIn: 1000 * 60 * 60 * 24
});
```

### rotateSessionId

Rotate a session ID for security.

```typescript
function rotateSessionId<TUser extends User = User>(
  session: Session<TUser>,
  storage: SessionStorageAdapter<TUser>
): Promise<Session<TUser>>
```

### generateSessionId

Generate a cryptographically secure session ID.

```typescript
function generateSessionId(length?: number): string
```

**Parameters:**
- `length`: Length of ID in bytes (default: 32)

### invalidateSession

Delete a session from storage.

```typescript
function invalidateSession<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  sessionId: string,
  options?: InvalidateOptions
): Promise<void>
```

**Options:**
```typescript
interface InvalidateOptions {
  reason?: string;       // Reason for invalidation
  notifyUser?: boolean;  // Send notification
}
```

### invalidateUserSessions

Delete all sessions for a user.

```typescript
function invalidateUserSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  options?: InvalidateUserSessionsOptions
): Promise<void>
```

**Options:**
```typescript
interface InvalidateUserSessionsOptions extends InvalidateOptions {
  except?: string; // Session ID to keep
}
```

### invalidateAllSessions

Delete all sessions across all users.

```typescript
function invalidateAllSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>
): Promise<void>
```

### listUserSessions

Get all sessions for a user.

```typescript
function listUserSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  options?: ListUserSessionsOptions
): Promise<SessionInfo[]>
```

**Options:**
```typescript
interface ListUserSessionsOptions {
  sortBy?: 'createdAt' | 'expiresAt';
  order?: 'asc' | 'desc';
}
```

**Returns:**
```typescript
interface SessionInfo {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  deviceInfo?: FingerprintMetadata;
}
```

### countUserSessions

Count active sessions for a user.

```typescript
function countUserSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string
): Promise<number>
```

### revokeDeviceSession

Revoke a specific device session.

```typescript
function revokeDeviceSession<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  deviceId: string
): Promise<void>
```

### enforceConcurrentSessionLimit

Enforce maximum concurrent sessions limit.

```typescript
function enforceConcurrentSessionLimit<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  maxSessions: number
): Promise<void>
```

### findSessionByDevice

Find a session by device fingerprint.

```typescript
function findSessionByDevice<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  deviceFingerprint: string
): Promise<Session<TUser> | null>
```

---

## Session Fingerprinting

### generateSessionFingerprint

Generate a session fingerprint from metadata.

```typescript
function generateSessionFingerprint(
  metadata: FingerprintMetadata
): string
```

**Metadata:**
```typescript
interface FingerprintMetadata {
  userAgent?: string;
  ip?: string;
  acceptLanguage?: string;
  platform?: string;
  [key: string]: string | undefined;
}
```

**Returns:** SHA-256 hash string

**Example:**
```typescript
const fingerprint = generateSessionFingerprint({
  userAgent: req.headers['user-agent'],
  ip: req.ip,
  acceptLanguage: req.headers['accept-language']
});
```

### validateFingerprint

Validate a session fingerprint.

```typescript
function validateFingerprint<TUser extends User = User>(
  session: Session<TUser>,
  currentMetadata: FingerprintMetadata,
  options?: FingerprintValidationOptions
): boolean
```

**Options:**
```typescript
interface FingerprintValidationOptions {
  strict?: boolean;        // Throw error on mismatch
  allowMissing?: boolean;  // Allow sessions without fingerprints
  message?: string;        // Custom error message
}
```

### compareFingerprints

Compare two fingerprints for equality (constant-time).

```typescript
function compareFingerprints(
  fingerprint1: string | undefined,
  fingerprint2: string | undefined
): boolean
```

### extractFingerprintMetadata

Extract fingerprint metadata from a request object.

```typescript
function extractFingerprintMetadata(
  request: {
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  },
  overrides?: Partial<FingerprintMetadata>
): FingerprintMetadata
```

---

## Storage Adapters

### SessionStorageAdapter

Interface for session storage implementations.

```typescript
interface SessionStorageAdapter<T = unknown> {
  get(sessionId: string): Promise<SessionEntry<T> | null>;
  set(sessionId: string, entry: SessionEntry<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
  
  // Optional methods
  getAllForUser?(userId: string): Promise<SessionEntry<T>[]>;
  deleteAllForUser?(userId: string): Promise<void>;
  count?(): Promise<number>;
}
```

**Session Entry:**
```typescript
interface SessionEntry<T = unknown> {
  sessionId: string;
  userId: string;
  data: T;
  createdAt: number;
  expiresAt: number;
  metadata?: Record<string, unknown>;
}
```

### MemoryStorageAdapter

Built-in memory storage with automatic cleanup.

```typescript
class MemoryStorageAdapter<T = unknown> implements SessionStorageAdapter<T> {
  constructor(options?: MemoryStorageOptions);
  
  get(sessionId: string): Promise<SessionEntry<T> | null>;
  set(sessionId: string, entry: SessionEntry<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
  getAllForUser(userId: string): Promise<SessionEntry<T>[]>;
  deleteAllForUser(userId: string): Promise<void>;
  count(): Promise<number>;
  getStats(): MemoryStorageStats;
  destroy(): void;
}
```

**Options:**
```typescript
interface MemoryStorageOptions {
  cleanupInterval?: number; // Cleanup interval in ms (default: 5 minutes)
  maxSize?: number;         // Maximum sessions to store
}
```

**Stats:**
```typescript
interface MemoryStorageStats {
  totalSessions: number;
  expiredSessions: number;
  activeSessions: number;
  userSessions: Map<string, number>;
}
```

---

## Guards & Route Protection

### requireAuth

Require authenticated user.

```typescript
function requireAuth<T = unknown>(
  options: RequireAuthOptions
): GuardFunction<T>
```

**Options:**
```typescript
interface RequireAuthOptions {
  storage: SessionStorageAdapter;
  getSessionId: (context: GuardContext) => Promise<string | undefined>;
  onSuccess: (context: GuardContext) => Promise<unknown>;
  onFailure: (context: GuardContext) => Promise<unknown>;
  validateFingerprint?: boolean;
  fingerprintMetadata?: (context: GuardContext) => FingerprintMetadata;
}
```

**Example:**
```typescript
const guard = requireAuth({
  storage,
  getSessionId: async (ctx) => ctx.request?.cookies?.session,
  onSuccess: async (ctx) => ({ userId: ctx.session.userId }),
  onFailure: async () => ({ error: 'Unauthorized' })
});
```

### requireGuest

Require unauthenticated user.

```typescript
function requireGuest(
  options: RequireGuestOptions
): GuardFunction
```

**Options:**
```typescript
interface RequireGuestOptions {
  storage?: SessionStorageAdapter;
  getSessionId?: (context: GuardContext) => Promise<string | undefined>;
  onSuccess: (context: GuardContext) => Promise<unknown>;
  onFailure?: (context: GuardContext) => Promise<unknown>;
}
```

### requireAny

Require at least one guard to pass (OR logic).

```typescript
function requireAny<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### requireAll

Require all guards to pass (AND logic).

```typescript
function requireAll<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### chainGuards

Execute guards sequentially.

```typescript
function chainGuards<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### allowAll

Always allow access.

```typescript
function allowAll<T = unknown>(data?: T): GuardFunction<T>
```

### denyAll

Always deny access.

```typescript
function denyAll(options?: {
  message?: string;
  statusCode?: number;
}): GuardFunction
```

### conditionalGuard

Execute guard based on condition.

```typescript
function conditionalGuard<T = unknown>(
  options: {
    condition: (context: GuardContext<T>) => Promise<boolean>;
    guardIfTrue: GuardFunction<T>;
    guardIfFalse: GuardFunction<T>;
  }
): GuardFunction<T>
```

### Guard Types

```typescript
type GuardFunction<T = unknown> = (
  context: GuardContext
) => Promise<GuardResult<T>>;

interface GuardContext {
  request?: unknown;
  session?: Session;
}

interface GuardResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  redirect?: string;
}
```

---

## Redirect Management

### isValidRedirect

Validate a redirect URL for security.

```typescript
function isValidRedirect(
  url: string,
  options?: RedirectValidationOptions
): boolean
```

**Options:**
```typescript
interface RedirectValidationOptions {
  allowedDomains?: string[];  // Allowed domains
  allowRelative?: boolean;    // Allow relative URLs
  allowSubdomains?: boolean;  // Allow subdomains
  maxLength?: number;         // Max URL length
}
```

### saveAuthRedirect

Save a redirect URL for after authentication.

```typescript
function saveAuthRedirect(
  storage: RedirectStorage,
  key: string,
  url: string,
  options?: SaveRedirectOptions
): Promise<void>
```

**Options:**
```typescript
interface SaveRedirectOptions extends RedirectValidationOptions {
  ttl?: number; // Time to live in milliseconds
}
```

### restoreAuthRedirect

Restore and remove a saved redirect URL.

```typescript
function restoreAuthRedirect(
  storage: RedirectStorage,
  key: string,
  options?: RestoreRedirectOptions
): Promise<string | null>
```

**Options:**
```typescript
interface RestoreRedirectOptions extends RedirectValidationOptions {
  fallback?: string; // Default URL if none saved
}
```

### peekAuthRedirect

View saved redirect without removing it.

```typescript
function peekAuthRedirect(
  storage: RedirectStorage,
  key: string
): Promise<string | null>
```

### clearAuthRedirect

Clear a saved redirect URL.

```typescript
function clearAuthRedirect(
  storage: RedirectStorage,
  key: string
): Promise<void>
```

**Redirect Storage:**
```typescript
interface RedirectStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
}
```

---

## Cookie Management

### createAuthCookie

Create a cookie string with options.

```typescript
function createAuthCookie(
  name: string,
  value: string,
  options?: CookieOptions
): string
```

**Options:**
```typescript
interface CookieOptions {
  maxAge?: number;              // Max age in seconds
  expires?: Date;               // Expiration date
  path?: string;                // Cookie path
  domain?: string;              // Cookie domain
  secure?: boolean;             // Secure flag (HTTPS only)
  httpOnly?: boolean;           // HttpOnly flag
  sameSite?: 'strict' | 'lax' | 'none'; // SameSite policy
  partitioned?: boolean;        // Partitioned attribute (CHIPS)
}
```

**Example:**
```typescript
const cookie = createAuthCookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 60 * 60 * 24
});
```

### createAuthCookies

Create multiple cookies at once.

```typescript
function createAuthCookies(
  cookies: Array<{ name: string; value: string; options?: CookieOptions }>
): string[]
```

### parseAuthCookies

Parse all cookies from Cookie header.

```typescript
function parseAuthCookies(
  cookieHeader: string | undefined
): Record<string, string>
```

### getAuthCookie

Get a specific cookie value.

```typescript
function getAuthCookie(
  cookieHeader: string | undefined,
  name: string
): string | undefined
```

### hasAuthCookie

Check if a cookie exists.

```typescript
function hasAuthCookie(
  cookieHeader: string | undefined,
  name: string
): boolean
```

### parseSetCookie

Parse a Set-Cookie header.

```typescript
function parseSetCookie(setCookieHeader: string): ParsedCookie | null
```

**Returns:**
```typescript
interface ParsedCookie {
  name: string;
  value: string;
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned: boolean;
}
```

### Validation Functions

```typescript
function isValidCookieName(name: string): boolean
function isValidCookieValue(value: string): boolean
function estimateCookieSize(name: string, value: string, options?: CookieOptions): number
```

---

## Cookie Signing (HMAC)

### signCookie

Sign a cookie value with HMAC-SHA256.

```typescript
function signCookie(value: string, secret: string): string
```

**Example:**
```typescript
const signed = signCookie('session_123', 'your-secret-key');
// Returns: "session_123.signature"
```

### unsignCookie

Verify and extract value from signed cookie.

```typescript
function unsignCookie(
  signedValue: string | undefined,
  secret: string
): { valid: boolean; value?: string }
```

### verifyCookieSignature

Verify a cookie signature.

```typescript
function verifyCookieSignature(
  value: string,
  signature: string,
  secret: string
): boolean
```

### signAndCreateCookie

Sign and create a cookie in one step.

```typescript
function signAndCreateCookie(
  name: string,
  value: string,
  secret: string,
  options?: CookieOptions
): string
```

### unsignCookieStrict

Verify signed cookie, throw on failure.

```typescript
function unsignCookieStrict(
  signedValue: string,
  secret: string
): string
```

**Throws:** `CookieSignatureError`

```typescript
class CookieSignatureError extends Error {
  constructor(message: string);
}
```

---

## Cookie Encryption (AES-256-GCM)

### encryptCookie

Encrypt a cookie value with AES-256-GCM.

```typescript
function encryptCookie(value: string, secret: string): string
```

**Example:**
```typescript
const encrypted = encryptCookie('session_123', 'your-secret-key');
// Returns: "iv:authTag:ciphertext"
```

### decryptCookie

Decrypt an encrypted cookie value.

```typescript
function decryptCookie(
  encryptedValue: string | undefined,
  secret: string
): { valid: boolean; value?: string }
```

### verifyEncryptedCookie

Verify encrypted cookie can be decrypted.

```typescript
function verifyEncryptedCookie(
  encryptedValue: string,
  secret: string
): boolean
```

### encryptAndCreateCookie

Encrypt and create a cookie in one step.

```typescript
function encryptAndCreateCookie(
  name: string,
  value: string,
  secret: string,
  options?: CookieOptions
): string
```

### decryptCookieStrict

Decrypt cookie, throw on failure.

```typescript
function decryptCookieStrict(
  encryptedValue: string,
  secret: string
): string
```

**Throws:** `CookieDecryptionError`

```typescript
class CookieDecryptionError extends Error {
  constructor(message: string);
}
```

---

## Cookie Deletion

### deleteAuthCookie

Create a cookie deletion string.

```typescript
function deleteAuthCookie(
  name: string,
  options?: Partial<CookieOptions>
): string
```

### deleteAuthCookies

Delete multiple cookies.

```typescript
function deleteAuthCookies(
  names: string[],
  options?: Partial<CookieOptions>
): string[]
```

### deleteAuthCookieExact

Delete cookie with exact path and domain.

```typescript
function deleteAuthCookieExact(
  name: string,
  path: string,
  domain?: string
): string
```

### deleteAuthCookieAllPaths

Delete cookie from all possible paths.

```typescript
function deleteAuthCookieAllPaths(
  name: string,
  paths: string[],
  domain?: string
): string[]
```

---

## Cookie Rotation

### rotateCookie

Rotate a cookie value.

```typescript
function rotateCookie(
  name: string,
  oldValue: string,
  newValue: string,
  options?: CookieOptions
): CookieRotationResult
```

**Returns:**
```typescript
interface CookieRotationResult {
  oldCookie: string;  // Cookie to delete
  newCookie: string;  // New cookie to set
}
```

### rotateCookies

Rotate multiple cookies.

```typescript
function rotateCookies(
  rotations: Array<{
    name: string;
    oldValue: string;
    newValue: string;
    options?: CookieOptions;
  }>
): CookieRotationResult[]
```

### rotateSignedCookie

Rotate a signed cookie.

```typescript
function rotateSignedCookie(
  name: string,
  oldValue: string,
  newValue: string,
  secret: string,
  options?: CookieOptions
): CookieRotationResult
```

### rotateEncryptedCookie

Rotate an encrypted cookie.

```typescript
function rotateEncryptedCookie(
  name: string,
  oldValue: string,
  newValue: string,
  secret: string,
  options?: CookieOptions
): Promise<CookieRotationResult>
```

### shouldRotateCookie

Determine if a cookie should be rotated.

```typescript
function shouldRotateCookie(
  createdAt: number,
  rotationInterval: number
): boolean
```

---

## Error Handling

### Base Error Classes

```typescript
class AuthUtilsError extends Error {
  code: string;
  statusCode: number;
  isOperational: boolean;
  metadata?: Record<string, unknown>;
  timestamp: number;
  
  constructor(
    message: string,
    code: string,
    statusCode: number,
    metadata?: Record<string, unknown>
  );
  
  toJSON(): {
    code: string;
    message: string;
    statusCode: number;
    timestamp: number;
    metadata?: Record<string, unknown>;
  };
}

class AuthError extends AuthUtilsError {
  // Alias for AuthUtilsError
}
```

### Authentication Errors

```typescript
class UnauthenticatedError extends AuthUtilsError
  // HTTP 401 - User not authenticated

class AuthenticationError extends AuthUtilsError
  // HTTP 401 - Authentication failed

class AlreadyAuthenticatedError extends AuthUtilsError
  // HTTP 400 - User already authenticated

class InvalidTokenError extends AuthUtilsError
  // HTTP 401 - Invalid token

class FingerprintMismatchError extends AuthUtilsError
  // HTTP 401 - Session fingerprint mismatch
```

### Authorization Errors

```typescript
class UnauthorizedError extends AuthUtilsError
  // HTTP 403 - Insufficient permissions

class AuthorizationError extends AuthUtilsError
  // HTTP 403 - Authorization failed
```

### Session Errors

```typescript
class SessionNotFoundError extends AuthUtilsError {
  sessionId?: string;
  // HTTP 404 - Session not found
}

class SessionExpiredError extends AuthUtilsError
  // HTTP 401 - Session expired

class InvalidSessionError extends AuthUtilsError
  // HTTP 401 - Session invalid

class UnauthorizedSessionAccessError extends AuthUtilsError
  // HTTP 403 - Unauthorized session access
```

### Validation Errors

```typescript
class ValidationError extends AuthUtilsError {
  fields?: Record<string, string>;
  // HTTP 400 - Validation failed
}

class InvalidInputError extends AuthUtilsError
  // HTTP 400 - Invalid input

class MissingFieldError extends AuthUtilsError
  // HTTP 400 - Required field missing
```

### Security Errors

```typescript
class RateLimitError extends AuthUtilsError
  // HTTP 429 - Rate limit exceeded

class CSRFError extends AuthUtilsError
  // HTTP 403 - CSRF validation failed

class InvalidRedirectError extends AuthUtilsError
  // HTTP 400 - Invalid redirect URL
```

---

## Error Type Guards

### isAuthUtilsError

Check if error is an AuthUtilsError.

```typescript
function isAuthUtilsError(error: unknown): error is AuthUtilsError
```

### isOperationalError

Check if error is operational (expected).

```typescript
function isOperationalError(error: unknown): boolean
```

### isSessionError

Check if error is session-related.

```typescript
function isSessionError(
  error: unknown
): error is SessionNotFoundError 
  | SessionExpiredError 
  | InvalidSessionError 
  | UnauthorizedSessionAccessError
```

### isAuthenticationError

Check if error is authentication-related.

```typescript
function isAuthenticationError(
  error: unknown
): error is UnauthenticatedError | AuthenticationError
```

### isAuthorizationError

Check if error is authorization-related.

```typescript
function isAuthorizationError(
  error: unknown
): error is AuthorizationError
```

### isValidationError

Check if error is a validation error.

```typescript
function isValidationError(error: unknown): error is ValidationError
```

### Error Utilities

```typescript
function getErrorStatusCode(error: unknown): number
  // Get HTTP status code (500 for unknown errors)

function getErrorCode(error: unknown): string
  // Get error code ('INTERNAL_ERROR' for unknown)

function serializeError(error: unknown): {
  code: string;
  message: string;
  statusCode: number;
  timestamp: number;
  metadata?: Record<string, unknown>;
}
  // Serialize error to JSON
```

---

## TypeScript Types

### Core Types

```typescript
interface User {
  id: string;
  [key: string]: unknown;
}

interface Session<TUser extends User = User> {
  id: string;
  user: TUser;
  createdAt: Date;
  expiresAt: Date;
}

interface SessionOptions {
  expiresIn?: number;
  absoluteTimeout?: number;
  renewalTimeout?: number;
}

interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned?: boolean;
}
```

### Context Types

```typescript
interface RequestContext {
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
  ip?: string;
  [key: string]: unknown;
}

interface ResponseContext {
  statusCode?: number;
  headers?: Record<string, string>;
  [key: string]: unknown;
}
```

---

## Next Steps

- [Introduction](/guide/introduction) - Learn about the library
- [Session Management Guide](/guide/sessions) - Complete session features
- [Guards Guide](/guide/guards) - Route protection patterns
- [Cookies Guide](/guide/cookies) - Secure cookie handling  
- [Error Handling Guide](/guide/errors) - Error management

### createSession

Create a new session for a user.

```typescript
function createSession<T = unknown>(
  userId: string,
  options?: SessionOptions<T>
): Session<T>
```

**Parameters:**
- `userId`: User identifier
- `options`: Session configuration options

**Options:**
- `expiresIn`: Session lifetime in milliseconds
- `idleTimeout`: Idle timeout in milliseconds
- `absoluteTimeout`: Maximum session lifetime
- `data`: Custom session data
- `fingerprint`: Session fingerprint hash

**Returns:** `Session<T>` object

**Example:**
```typescript
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24,
  data: { roles: ['admin'] }
});
```

### validateSession

Validate a session's expiration and timeouts.

```typescript
function validateSession<T = unknown>(
  session: Session<T>,
  options?: ValidationOptions
): ValidationResult
```

**Parameters:**
- `session`: Session to validate
- `options`: Validation options

**Options:**
- `idleTimeout`: Idle timeout in milliseconds
- `absoluteTimeout`: Absolute timeout in milliseconds
- `refreshThreshold`: Threshold for refresh suggestion (0-1)

**Returns:** 
```typescript
interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'idle-timeout' | 'absolute-timeout';
  shouldRefresh: boolean;
}
```

### refreshSession

Refresh a session, optionally rotating the session ID.

```typescript
async function refreshSession<T = unknown>(
  session: Session<T>,
  storage: SessionStorageAdapter<T>,
  options?: RefreshOptions
): Promise<Session<T>>
```

**Parameters:**
- `session`: Session to refresh
- `storage`: Storage adapter
- `options`: Refresh options

**Options:**
- `rotateId`: Generate new session ID (default: true)
- `expiresIn`: New expiration time in milliseconds

**Returns:** Refreshed `Session<T>` object

### invalidateSession

Delete a session from storage.

```typescript
async function invalidateSession<T = unknown>(
  storage: SessionStorageAdapter<T>,
  sessionId: string
): Promise<void>
```

### invalidateAllSessions

Delete all sessions for a user.

```typescript
async function invalidateAllSessions<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string
): Promise<void>
```

### Session Type

```typescript
interface Session<T = unknown> {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  lastActivityAt: number;
  data?: T;
  fingerprint?: string;
}
```

### SessionStorageAdapter

Interface for session storage implementations.

```typescript
interface SessionStorageAdapter<T = unknown> {
  get(sessionId: string): Promise<Session<T> | null>;
  set(sessionId: string, session: Session<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
}
```

### MemoryStorageAdapter

Built-in memory storage with automatic cleanup.

```typescript
class MemoryStorageAdapter<T = unknown> implements SessionStorageAdapter<T> {
  constructor(options?: MemoryStorageOptions);
  
  get(sessionId: string): Promise<Session<T> | null>;
  set(sessionId: string, session: Session<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
  destroy(): void;
}

interface MemoryStorageOptions {
  cleanupInterval?: number; // Cleanup interval in ms
  maxSize?: number; // Maximum sessions to store
}
```

## Multi-Device Sessions

### addDeviceSession

Add a device session for a user.

```typescript
async function addDeviceSession<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string,
  sessionId: string,
  metadata: FingerprintMetadata,
  options?: DeviceSessionOptions
): Promise<DeviceSession>
```

**Parameters:**
- `storage`: Storage adapter
- `userId`: User identifier
- `sessionId`: Session identifier
- `metadata`: Device fingerprint metadata
- `options`: Device session options

**Options:**
- `maxDevices`: Maximum concurrent devices
- `trustDevice`: Mark device as trusted

**Returns:** `DeviceSession` object

### getActiveDevices

Get all active devices for a user.

```typescript
async function getActiveDevices<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string
): Promise<DeviceSession[]>
```

### revokeDevice

Revoke a specific device session.

```typescript
async function revokeDevice<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string,
  deviceId: string
): Promise<void>
```

### revokeAllDevicesExcept

Revoke all devices except the specified one.

```typescript
async function revokeAllDevicesExcept<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string,
  keepDeviceId: string
): Promise<void>
```

## Session Fingerprinting

### generateSessionFingerprint

Generate a session fingerprint from metadata.

```typescript
function generateSessionFingerprint(
  metadata: FingerprintMetadata
): string
```

**Parameters:**
- `metadata`: Fingerprint metadata

```typescript
interface FingerprintMetadata {
  userAgent?: string;
  ip?: string;
  acceptLanguage?: string;
  platform?: string;
  [key: string]: string | undefined;
}
```

**Returns:** SHA-256 hash string

### validateFingerprint

Validate a session fingerprint.

```typescript
function validateFingerprint<T = unknown>(
  session: Session<T>,
  currentMetadata: FingerprintMetadata,
  options?: FingerprintValidationOptions
): boolean
```

**Options:**
- `strict`: Throw error on mismatch
- `allowMissing`: Allow sessions without fingerprints
- `message`: Custom error message

### extractFingerprintMetadata

Extract fingerprint metadata from a request object.

```typescript
function extractFingerprintMetadata(
  request: {
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  },
  overrides?: Partial<FingerprintMetadata>
): FingerprintMetadata
```

## Guards

### requireAuth

Require authenticated user.

```typescript
function requireAuth<T = unknown>(
  options: RequireAuthOptions<T>
): GuardFunction<T>
```

**Options:**
```typescript
interface RequireAuthOptions<T = unknown> {
  storage: SessionStorageAdapter<T>;
  getSessionId: (context: GuardContext<T>) => Promise<string | undefined>;
  onSuccess: (context: GuardContext<T>) => Promise<unknown>;
  onFailure: (context: GuardContext<T>) => Promise<unknown>;
  validateFingerprint?: boolean;
  fingerprintMetadata?: (context: GuardContext<T>) => FingerprintMetadata;
}
```

### requireGuest

Require unauthenticated user.

```typescript
function requireGuest<T = unknown>(
  options: RequireGuestOptions<T>
): GuardFunction<T>
```

**Options:**
```typescript
interface RequireGuestOptions<T = unknown> {
  storage?: SessionStorageAdapter<T>;
  getSessionId?: (context: GuardContext<T>) => Promise<string | undefined>;
  onSuccess: (context: GuardContext<T>) => Promise<unknown>;
  onFailure?: (context: GuardContext<T>) => Promise<unknown>;
}
```

### requireAny

Require at least one guard to pass (OR logic).

```typescript
function requireAny<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### requireAll

Require all guards to pass (AND logic).

```typescript
function requireAll<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### chainGuards

Execute guards sequentially.

```typescript
function chainGuards<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### allowAll

Always allow access.

```typescript
function allowAll<T = unknown>(
  options: AllowAllOptions<T>
): GuardFunction<T>
```

### conditionalGuard

Execute guard based on condition.

```typescript
function conditionalGuard<T = unknown>(
  options: ConditionalGuardOptions<T>
): GuardFunction<T>
```

**Options:**
```typescript
interface ConditionalGuardOptions<T = unknown> {
  condition: (context: GuardContext<T>) => Promise<boolean>;
  guardIfTrue: GuardFunction<T>;
  guardIfFalse: GuardFunction<T>;
}
```

### redirect

Create a redirect response.

```typescript
function redirect(
  url: string,
  options?: RedirectOptions
): RedirectResult
```

**Options:**
- `query`: Query parameters to append
- `allowedDomains`: Allowed domains for redirect
- `allowRelative`: Allow relative URLs

### Guard Types

```typescript
type GuardFunction<T = unknown> = (
  context: GuardContext<T>
) => Promise<GuardResult<T>>;

interface GuardContext<T = unknown> {
  request?: unknown;
  session?: Session<T>;
}

type GuardResult<T = unknown> = unknown;
```

## Cookies

### createCookie

Create a cookie string.

```typescript
function createCookie(
  name: string,
  value: string,
  options?: CookieOptions
): string
```

**Options:**
```typescript
interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned?: boolean;
}
```

### parseCookie

Parse a cookie from Cookie header.

```typescript
function parseCookie(
  cookieHeader: string | undefined,
  name: string
): ParsedCookie | null
```

### parseCookies

Parse all cookies from Cookie header.

```typescript
function parseCookies(
  cookieHeader: string | undefined
): Record<string, string>
```

### getCookieValue

Get a cookie value from Cookie header.

```typescript
function getCookieValue(
  cookieHeader: string | undefined,
  name: string
): string | undefined
```

### signCookie

Sign a cookie with HMAC-SHA256.

```typescript
function signCookie(
  cookie: string,
  secret: string
): string
```

### verifyCookie

Verify a signed cookie.

```typescript
function verifyCookie(
  cookieHeader: string | undefined,
  name: string,
  secret: string,
  options?: VerifyOptions
): VerifyResult
```

**Returns:**
```typescript
interface VerifyResult {
  valid: boolean;
  value?: string;
  error?: string;
}
```

### encryptCookie

Encrypt a cookie with AES-256-GCM.

```typescript
async function encryptCookie(
  cookie: string,
  secret: string
): Promise<string>
```

### decryptCookie

Decrypt an encrypted cookie.

```typescript
async function decryptCookie(
  cookieHeader: string | undefined,
  name: string,
  secret: string,
  options?: DecryptOptions
): Promise<DecryptResult>
```

**Returns:**
```typescript
interface DecryptResult {
  valid: boolean;
  value?: string;
  error?: string;
}
```

### rotateCookie

Rotate a cookie value.

```typescript
function rotateCookie(
  cookie: string,
  newValue: string
): string
```

### deleteCookie

Create a cookie deletion string.

```typescript
function deleteCookie(
  name: string,
  options?: Partial<CookieOptions>
): string
```

### deleteAllCookies

Create deletion strings for multiple cookies.

```typescript
function deleteAllCookies(
  names: string[],
  options?: Partial<CookieOptions>
): string[]
```

## Errors

### Error Classes

```typescript
// Authentication Errors
class UnauthenticatedError extends AuthError
class InvalidCredentialsError extends AuthError
class AccountLockedError extends AuthError
class FingerprintMismatchError extends AuthError

// Session Errors
class SessionExpiredError extends AuthError
class SessionNotFoundError extends AuthError
class SessionRevokedError extends AuthError
class ConcurrentSessionError extends AuthError
class InvalidSessionError extends AuthError

// Cookie Errors
class InvalidCookieError extends AuthError
class CookieSignatureMismatchError extends AuthError
class CookieDecryptionError extends AuthError

// Token Errors
class InvalidTokenError extends AuthError
class TokenExpiredError extends AuthError
class TokenRevokedError extends AuthError

// Validation Errors
class ValidationError extends AuthError

// Authorization Errors
class UnauthorizedError extends AuthError
class ForbiddenError extends AuthError
class InsufficientPermissionsError extends AuthError
```

### Base Error Class

```typescript
class AuthError extends Error {
  code: string;
  statusCode: number;
  metadata?: Record<string, unknown>;
  timestamp: number;
  
  toJSON(): {
    code: string;
    message: string;
    statusCode: number;
    timestamp: number;
    metadata?: Record<string, unknown>;
  };
}
```

### Type Guards

```typescript
// General
function isAuthError(error: unknown): error is AuthError

// Authentication
function isAuthenticationError(error: unknown): boolean
function isUnauthenticatedError(error: unknown): error is UnauthenticatedError
function isInvalidCredentialsError(error: unknown): error is InvalidCredentialsError
function isAccountLockedError(error: unknown): error is AccountLockedError

// Session
function isSessionError(error: unknown): boolean
function isSessionExpiredError(error: unknown): error is SessionExpiredError
function isSessionNotFoundError(error: unknown): error is SessionNotFoundError
function isSessionRevokedError(error: unknown): error is SessionRevokedError

// Cookie
function isCookieError(error: unknown): boolean
function isInvalidCookieError(error: unknown): error is InvalidCookieError
function isCookieSignatureMismatchError(error: unknown): error is CookieSignatureMismatchError

// Token
function isTokenError(error: unknown): boolean
function isInvalidTokenError(error: unknown): error is InvalidTokenError
function isTokenExpiredError(error: unknown): error is TokenExpiredError

// Validation
function isValidationError(error: unknown): error is ValidationError

// Authorization
function isAuthorizationError(error: unknown): boolean
function isUnauthorizedError(error: unknown): error is UnauthorizedError
function isForbiddenError(error: unknown): error is ForbiddenError
```

## TypeScript Types

### Main Types

```typescript
// Sessions
interface Session<T = unknown> {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  lastActivityAt: number;
  data?: T;
  fingerprint?: string;
}

interface SessionOptions<T = unknown> {
  expiresIn?: number;
  idleTimeout?: number;
  absoluteTimeout?: number;
  data?: T;
  fingerprint?: string;
}

interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'idle-timeout' | 'absolute-timeout';
  shouldRefresh: boolean;
}

// Device Sessions
interface DeviceSession {
  deviceId: string;
  userId: string;
  sessionId: string;
  fingerprint: string;
  trusted: boolean;
  createdAt: number;
}

// Cookies
interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned?: boolean;
}

interface ParsedCookie {
  name: string;
  value: string;
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned: boolean;
}

// Guards
type GuardFunction<T = unknown> = (
  context: GuardContext<T>
) => Promise<GuardResult<T>>;

interface GuardContext<T = unknown> {
  request?: unknown;
  session?: Session<T>;
}

type GuardResult<T = unknown> = unknown;
```

## Next Steps

- [Session Management Guide](/guide/sessions)
- [Guards Guide](/guide/guards)
- [Cookies Guide](/guide/cookies)
- [Error Handling Guide](/guide/errors)
