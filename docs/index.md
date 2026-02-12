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
  
  - title: Route Protection Guards
    details: Composable authentication guards with redirect management and open redirect prevention
  
  - title: Secure Cookie Utilities
    details: RFC 6265 compliant with HMAC signing and AES-256-GCM encryption
  
  - title: Enterprise Error Handling
    details: 17+ specialized errors with HTTP status codes and type guards
  
  - title: Tree-Shakeable Modules
    details: Import only what you need - ~4.4KB total, fully modular
  
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

## What's New in v1.1.0

### Major Features

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

- **375 tests** passing (100% pass rate)
- **>95% coverage** across all modules
- **~4.4KB total** bundle size (tree-shakeable)
- **Zero dependencies** (Node.js built-ins only)

## Why @amtarc/auth-utils?

Unlike full authentication frameworks, `@amtarc/auth-utils` provides **focused utilities** you can integrate anywhere:

**Perfect for:**
- Enhancing existing auth setups (Auth.js, Better Auth, Clerk)
- Building custom authentication flows
- Serverless and edge environments
- Microservices architectures
- Adding advanced session features

**Key Advantages:**
- Truly framework-agnostic
- Minimal bundle size (~4.4KB vs 50KB+)
- Tree-shakeable modular exports
- Multi-device session support built-in
- Session fingerprinting included
- Cookie encryption out of the box
- Enterprise-grade error handling

## Modular Design

Import only what you need:

```typescript
// Full imports
import { createSession, requireAuth } from '@amtarc/auth-utils';

// Or use specific modules
import { refreshSession } from '@amtarc/auth-utils/session';
import { requireGuest } from '@amtarc/auth-utils/guards';
import { signCookie } from '@amtarc/auth-utils/cookies';
import { UnauthenticatedError } from '@amtarc/auth-utils/errors';
```
