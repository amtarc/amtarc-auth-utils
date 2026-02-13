---
layout: home
hero:
  name: "@amtarc/auth-utils"
  text: Enterprise Authentication Utilities
  tagline: Production-ready authentication utilities with session management, guards, secure cookies, and comprehensive error handling
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/amtarc/amtarc-auth-utils

features:
  - title: Advanced Session Management
    details: Multi-device sessions, fingerprinting, storage adapters, and automatic rotation
  
  - title: Security Features
    details: CSRF protection, rate limiting, brute force protection, encryption, and security headers
  
  - title: Unified Storage Layer
    details: Universal storage adapters for sessions, CSRF, and rate limiting with type-safe integration
  
  - title: Route Protection Guards
    details: Composable authentication guards with redirect management and open redirect prevention
  
  - title: Secure Cookie Utilities
    details: RFC 6265 compliant with HMAC signing and AES-256-GCM encryption
  
  - title: Enterprise Error Handling
    details: 17+ specialized errors with HTTP status codes and type guards
  
  - title: Tree-Shakeable Modules
    details: Import only what you need - fully modular architecture
  
  - title: Type-Safe & Framework Agnostic
    details: Full TypeScript support, works with Express, Next.js, Fastify, and more
---

## Quick Start

```bash
npm install @amtarc/auth-utils
```

```typescript
import { createSession, requireAuth } from '@amtarc/auth-utils';
import { createAuthCookie, signCookie } from '@amtarc/auth-utils/cookies';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

// Setup storage
const storage = new MemoryStorageAdapter();

// Create and store session
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  idleTimeout: 1000 * 60 * 30, // 30 minutes
});
await storage.set(session.sessionId, session);

// Create signed cookie
const cookie = signCookie(
  createAuthCookie('session', session.sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
  }),
  'your-secret-key'
);

// Protect routes
const handler = requireAuth(async (context) => {
  return { user: context.session.userId };
});
```

## What's New in v1.2.0

### Phase 3: Security & Storage (Latest)

**Unified Storage Layer:**
- `BaseStorage` and `CounterStorage` interfaces
- `UniversalMemoryStorage` - single adapter for all modules
- Type-safe storage adapters with TTL support
- Cross-module storage sharing
- Session-specific methods (getUserSessions, touch, cleanup)

**Security Features:**
- CSRF protection (synchronizer token & double-submit)
- Rate limiting (4 algorithms: fixed window, sliding window, token bucket)
- Brute force protection with account lockout
- Security headers (CSP, HSTS, X-Frame-Options)
- AES-256-GCM encryption with key derivation
- Cryptographically secure random generation

**Integration:**
- `SessionCSRFAdapter` - store CSRF tokens in sessions
- Universal storage for sessions + CSRF + rate limiting
- Type-safe cross-module integration
- Complete documentation and examples

### Phase 2: Security Foundations

**CSRF Protection:**
- Synchronizer token pattern
- Double-submit cookie pattern
- Token rotation and lifecycle
- Session integration

**Rate Limiting:**
- Multiple algorithms (fixed, sliding, token bucket)
- Brute force protection
- IP and user-based limits
- Flexible storage adapters

**Encryption & Headers:**
- AES-256-GCM encryption
- PBKDF2 and Scrypt key derivation
- Security headers builder
- CSP with nonce support

### Phase 1: Core Authentication (v1.1.0)

**Session Management:**
- Multi-device session support with tracking and limits
- Session fingerprinting for device identification
- Storage adapters (Memory + custom)
- Session refresh and ID rotation

**Guards & Route Protection:**
- `requireAuth` and `requireGuest` guards
- Composable guards (`requireAny`, `requireAll`)
- Redirect management with security validations

**Cookie Management:**
- Secure cookie creation/parsing (RFC 6265)
- HMAC-SHA256 signing
- AES-256-GCM encryption
- Cookie rotation and deletion

**Error Handling:**
- 17 specialized error classes
- HTTP status code mapping
- Type guards for error classification
- JSON serialization for APIs

### Stats

- **557 tests** passing (100% pass rate)
- **>95% coverage** across all modules
- **42KB ESM** bundle size (tree-shakeable)
- **Zero dependencies** (Node.js built-ins only)

## Why @amtarc/auth-utils?

Unlike full authentication frameworks, `@amtarc/auth-utils` provides **focused utilities** you can integrate anywhere:

**Perfect for:**
- Enhancing existing auth setups (Auth.js, Better Auth, Clerk)
- Building custom authentication flows
- Serverless and edge environments
- Microservices architectures
- Adding advanced session features
- Implementing CSRF and rate limiting

**Key Advantages:**
- Truly framework-agnostic
- Minimal bundle size (tree-shakeable)
- Multi-device session support built-in
- Session fingerprinting included
- CSRF protection out of the box
- Rate limiting with multiple algorithms
- Unified storage layer for all features
- Cookie encryption and signing
- Enterprise-grade error handling
- Zero dependencies

## Modular Design

Import only what you need:

```typescript
// Core features
import { createSession, requireAuth } from '@amtarc/auth-utils';

// Session management
import { refreshSession } from '@amtarc/auth-utils/session';

// Guards
import { requireGuest, requireAny } from '@amtarc/auth-utils/guards';

// Cookies
import { signCookie, encryptCookie } from '@amtarc/auth-utils/cookies';

// Security features
import { 
  generateCSRFToken, 
  createRateLimiter,
  encrypt 
} from '@amtarc/auth-utils/security';

// Storage adapters
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';

// Error handling
import { UnauthenticatedError } from '@amtarc/auth-utils/errors';
```
