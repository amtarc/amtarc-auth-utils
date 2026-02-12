# Introduction

## What is @amtarc/auth-utils?

`@amtarc/auth-utils` is a **production-ready TypeScript library** that provides comprehensive authentication utilities for modern applications. It focuses on solving the complex, recurring patterns that aren't covered by standard authentication providers.

## The Problem We Solve

Modern authentication frameworks like Auth.js, Better Auth, and Clerk handle core authentication flows well (OAuth, credentials, magic links). However, production applications need additional utilities:

- **Session Management**: Multi-device sessions, fingerprinting, storage adapters, refresh & rotation
- **Route Protection**: Authentication guards with redirect handling and composable logic
- **Cookie Security**: RFC 6265 compliant with HMAC signing and AES-256-GCM encryption
- **Error Handling**: Specialized errors with HTTP status codes and type guards for consistent error handling

`@amtarc/auth-utils` provides battle-tested implementations of these utilities that integrate with any TypeScript application.

## Design Philosophy

### 1. Framework-Agnostic Core

All core functionality works independently of any framework. Use with Express, Next.js, Fastify, Hono, or any other framework.

### 2. Modular Architecture

Import only what you need. Every feature is tree-shakable to minimize bundle size (~4.4KB total).

```typescript
// Import specific modules
import { createSession } from '@amtarc/auth-utils/session';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { signCookie } from '@amtarc/auth-utils/cookies';
import { UnauthenticatedError } from '@amtarc/auth-utils/errors';

// Or use main exports
import { createSession, requireAuth } from '@amtarc/auth-utils';
```

### 3. Type-Safe by Default

Built with TypeScript's strictest settings. Generic types allow you to extend with your own data types.

```typescript
interface UserData {
  email: string;
  roles: string[];
}

const session = createSession<UserData>('user-123', {
  data: { email: 'user@example.com', roles: ['admin'] }
});
// session.data is typed as UserData
```

### 4. Security-First

Safe defaults, explicit overrides. All security-sensitive features require conscious opt-in for less secure options.

### 5. Production-Ready

Features like automatic session rotation, device fingerprinting, and comprehensive error handling are built-in.

## Core Features

### Session Management

Complete session lifecycle management with multi-device support:

- Session creation with configurable expiration
- Idle timeout and absolute timeout support
- Session refresh and ID rotation
- Multi-device session tracking with limits
- Session fingerprinting for device identification
- Storage adapters (Memory included, custom supported)
- Session invalidation (single device or all devices)

### Guards & Route Protection

Protect routes with composable guards:

- `requireAuth` - Require authenticated users
- `requireGuest` - Require unauthenticated users  
- `requireAny` - OR logic for multiple guards
- `requireAll` - AND logic for multiple guards
- `chainGuards` - Sequential guard execution
- `allowAll` - Always allow (for public routes)
- `conditionalGuard` - Dynamic guard selection
- Redirect management with open redirect prevention

### Cookie Utilities

Secure cookie creation and management:

- RFC 6265 compliant cookie creation/parsing
- HMAC-SHA256 signature signing and verification
- AES-256-GCM encryption and decryption
- Cookie rotation with single-use guarantees
- Secure deletion with past expiration
- Validation for cookie names, values, domains, paths

### Error Handling

Comprehensive error system with 17+ error types:

- **Authentication Errors**: `UnauthenticatedError`, `InvalidCredentialsError`
- **Session Errors**: `SessionExpiredError`, `SessionRevokedError`, `ConcurrentSessionError`
- **Cookie Errors**: `InvalidCookieError`, `CookieSignatureMismatchError`
- **Validation Errors**: `ValidationError` with field details
- **Token Errors**: `InvalidTokenError`, `TokenExpiredError`
- HTTP status code mapping for API responses
- Type guards for error classification
- JSON serialization support

## What's Included (v1.1.0)

The current release includes:

**@amtarc/auth-utils** (Core Package)
- Session management with multi-device support
- Authentication guards with composition
- Cookie utilities with security features
- Comprehensive error handling

**Bundle Size**: ~4.4KB total (tree-shakeable)  
**Test Coverage**: 375 tests, >95% coverage  
**Dependencies**: Zero (Node.js built-ins only)

## Next Steps

- [Installation](/guide/installation) - Get started with installation
- [Quick Start](/guide/quick-start) - Build your first protected route
- [Session Management](/guide/sessions) - Deep dive into sessions
- [Guards](/guide/guards) - Learn about route protection
- [Cookies](/guide/cookies) - Secure cookie handling
- [Error Handling](/guide/errors) - Handle errors properly

