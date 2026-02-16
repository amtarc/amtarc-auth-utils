# @amtarc/auth-utils

> Enterprise-grade authentication and security utilities with session management, guards, CSRF protection, rate limiting, encryption, security headers, and RBAC authorization

[![npm version](https://img.shields.io/npm/v/@amtarc/auth-utils.svg)](https://www.npmjs.com/package/@amtarc/auth-utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @amtarc/auth-utils
# or
pnpm add @amtarc/auth-utils
# or
yarn add @amtarc/auth-utils
```

## Features

### Session Management
- Session creation, validation, and refresh
- Multi-device session support (`listUserSessions`, `revokeDeviceSession`, `findSessionByDevice`)
- Session fingerprinting for device tracking
- Concurrent session limits with automatic enforcement
- Session invalidation (single device, all devices, all except current)
- Storage adapter pattern (Memory, custom adapters)
- Session ID rotation for security

### Guards & Route Protection
- Authentication guards (`requireAuth`, `requireGuest`)
- Composable guard system (`requireAny`, `requireAll`)
- Redirect management (`saveAuthRedirect`, `restoreAuthRedirect`, `peekAuthRedirect`, `clearAuthRedirect`, `isValidRedirect`)
- Open redirect prevention with domain validation
- Framework-agnostic design

### Cookie Management
- Secure cookie creation and parsing (RFC 6265)
- HMAC cookie signing (SHA-256)
- AES-256-GCM cookie encryption
- Cookie rotation and deletion
- Secure defaults (HttpOnly, Secure, SameSite)

### Security
- CSRF protection (double-submit & synchronizer patterns)
- Rate limiting (4 algorithms: token bucket, fixed window, sliding window)
- Brute-force protection with progressive delays
- Security headers (CSP, HSTS, X-Frame-Options, etc.)
- AES-256-GCM encryption with key derivation
- Secure random generation (tokens, UUIDs, etc.)

### Authorization
- **RBAC (Role-Based Access Control)** with permission inheritance
  - Scoped role assignments (tenant, organization, project)
  - Role hierarchy validation with circular dependency detection (up to 10 levels)
  - Permission and role management with auto-ID generation
  - Expiring role assignments with automatic cleanup
- **ABAC (Attribute-Based Access Control)** with policy engine
  - Policy evaluation with user attributes and context
  - Time-based policies and custom conditions
  - Policy combining algorithms (permit-overrides, deny-overrides)
- **Resource-based Access Control**
  - Grant/revoke access to specific resources
  - Resource ownership and access level management
  - Resource metadata and hierarchical permissions
- Authorization guards (`requirePermission`, `requireRole`, `requirePolicy`)
- Memory storage adapter (custom adapters supported)

### Error Handling
- 25+ specialized error classes
- HTTP status code mapping
- Type guards for error classification
- JSON serialization for API responses
- Operational vs programmer error distinction

### Developer Experience
- Full TypeScript support with generics
- Tree-shakeable modular exports
- Zero runtime dependencies
- Framework-agnostic
- Comprehensive JSDoc documentation

## Quick Start

```typescript
import { createSession } from '@amtarc/auth-utils';
import { createAuthCookie, signCookie } from '@amtarc/auth-utils/cookies';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { UnauthenticatedError } from '@amtarc/auth-utils/errors';

// Create a session
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  idleTimeout: 1000 * 60 * 30, // 30 minutes
});

// Create signed session cookie
const signedValue = signCookie(session.sessionId, 'your-secret-key');
const sessionCookie = createAuthCookie('session', signedValue, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
});

// Protect routes with guards
const guard = requireAuth();
const result = guard({
  session,
  request: { url: '/dashboard' },
  response: {},
});

if (!result.authorized) {
  throw new UnauthenticatedError('Please log in');
}
```

## Modular Imports

The package provides tree-shakeable exports:

```typescript
// Main entry (all features)
import { createSession } from '@amtarc/auth-utils';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { createAuthCookie } from '@amtarc/auth-utils/cookies';

// Session management only
import { 
  createSession,
  validateSession,
  refreshSession,
  invalidateSession
} from '@amtarc/auth-utils/session';

// Guards only
import { requireAuth, requireGuest, requireAny } from '@amtarc/auth-utils/guards';

// Cookies only
import { createAuthCookie, signCookie, encryptCookie } from '@amtarc/auth-utils/cookies';

// Errors only
import { UnauthenticatedError, SessionExpiredError } from '@amtarc/auth-utils/errors';

// Security
import { generateCSRFToken, createRateLimiter } from '@amtarc/auth-utils/security';
import { CSPBuilder, createSecurityHeaders } from '@amtarc/auth-utils/security/headers';
import { encrypt, deriveKey } from '@amtarc/auth-utils/security/encryption';

// Authorization
import { PermissionManager, RoleManager, RBACGuards } from '@amtarc/auth-utils/authorization';
import { MemoryRBACStorage } from '@amtarc/auth-utils/authorization/rbac';
```

## API Documentation

For complete API reference with all methods, parameters, and examples, see our [full documentation](https://amtarc-auth-utils.dev).

### Quick Reference

**Session Management:**
- `createSession()` - Create sessions with secure IDs
- `validateSession()` - Validate expiration and idle timeout
- `refreshSession()` - Update timestamps and rotate IDs
- `invalidateSession()` - End sessions
- `MemoryStorageAdapter` - In-memory session storage
- `listUserSessions()` / `revokeDeviceSession()` - Multi-device management
- `enforceConcurrentSessionLimit()` - Limit concurrent sessions
- `countUserSessions()` / `findSessionByDevice()` - Session queries
- `invalidateUserSessions()` - Bulk session invalidation
- `generateSessionFingerprint()` - Device tracking

**Guards & Protection:**
- `requireAuth()` - Require authenticated users
- `requireGuest()` - Require unauthenticated users
- `requireAny()` / `requireAll()` - Composable guards
- `saveAuthRedirect()` / `restoreAuthRedirect()` / `peekAuthRedirect()` - Redirect management
- `clearAuthRedirect()` / `isValidRedirect()` - Redirect utilities

**Cookie Management:**
- `createAuthCookie()` / `parseAuthCookies()` - Cookie strings
- `signCookie()` / `verifyCookie()` - HMAC signing
- `encryptCookie()` / `decryptCookie()` - AES-256-GCM encryption
- `deleteCookie()` / `rotateCookie()` - Cookie lifecycle

**Security:**
- `generateCSRFToken()` / `validateCSRFToken()` - CSRF protection
- `generateDoubleSubmitToken()` - Stateless CSRF
- `generateSynchronizerToken()` - Server-side CSRF
- `createRateLimiter()` - Rate limiting (4 algorithms)
- `BruteForceProtection` - Login protection
- `CSPBuilder` - Content Security Policy builder
- `createSecurityHeaders()` - Security headers collection
- `encrypt()` / `decrypt()` - AES-256-GCM encryption
- `deriveKey()` - PBKDF2/Scrypt key derivation
- `generateSecureToken()` - Cryptographic tokens

**Authorization:**
- `PermissionManager` - Define and manage permissions
- `RoleManager` - Create roles, grant permissions, assign to users
- `RoleHierarchy` - Validate role hierarchies with circular detection
- `PolicyEngine` - ABAC policy evaluation with attributes and conditions
- `ResourceManager` - Grant/revoke access to resources with ownership
- `RBACGuards` - Authorization guards (requireRole, requirePermission, requirePolicy)
- `MemoryRBACStorage` - In-memory storage with expiration
- Role inheritance (up to 10 levels)
- Scoped assignments (tenant, organization, project)
- Time-based policies and resource ownership

**Error Handling:**
- `AuthUtilsError` - Base error with HTTP status codes
- `UnauthenticatedError`, `UnauthorizedError` - Auth errors (401/403)
- `SessionExpiredError`, `SessionNotFoundError` - Session errors
- `CSRFError`, `RateLimitError` - Security errors (403/429)
- `InsufficientPermissionsError` - Authorization errors (403)
- `isAuthUtilsError()`, `getErrorStatusCode()` - Type guards
- `serializeError()` - Safe JSON serialization

## TypeScript Support

Full TypeScript support with generics:

```typescript
interface UserData {
  role: 'admin' | 'user';
  permissions: string[];
}

const session = createSession<UserData>('user-123', {
  data: {
    role: 'admin',
    permissions: ['read', 'write'],
  },
});

// session.data is typed as UserData
session.data.role; // 'admin' | 'user'
```

## Framework Integration

Framework-agnostic with adapter examples for Express, Next.js, Fastify, and more. See [documentation](https://amtarc-auth-utils.dev/guide/frameworks) for details.

## Bundle Size

- **Main (Full)**: ~12 KB (gzipped)

Total: ~12 KB (tree-shakeable - use only what you need)

## Testing

661 tests with >95% coverage:

```bash
pnpm test          # Run tests in watch mode
pnpm test:run      # Run tests once
pnpm test:coverage # Generate coverage report
```

## License

MIT
