# Introduction

## What is amtarc-auth-utils?

`amtarc-auth-utils` is an **enterprise-grade TypeScript library** that provides comprehensive authentication and authorization utilities for production applications.

Unlike full authentication frameworks, `amtarc-auth-utils` focuses on solving the complex, recurring patterns that enterprises face but aren't solved by standard auth providers.

## The Problem We Solve

Modern authentication frameworks like Auth.js, Better Auth, and Clerk do an excellent job of handling core authentication flows (OAuth, credentials, magic links, etc.). However, production applications need much more:

- **Session Management**: Multi-device sessions, session fingerprinting, concurrent session limits
- **Authorization**: RBAC, ABAC, resource-based permissions with policy evaluation
- **Security**: CSRF protection, rate limiting, security headers, brute-force prevention
- **Multi-Tenancy**: Tenant isolation, context management, cross-tenant prevention
- **Compliance**: Audit logging for GDPR, SOC 2, and other regulations
- **Observability**: Metrics, tracing, and structured logging for production monitoring

Building these features from scratch is time-consuming and error-prone. `amtarc-auth-utils` provides battle-tested implementations that you can integrate into any TypeScript application.

## Design Philosophy

### 1. Framework-Agnostic Core

All core functionality works independently of any framework. Optional adapters provide convenience for popular frameworks like Express, Next.js, and Fastify.

### 2. Modular Architecture

Import only what you need. Every feature is tree-shakable to minimize bundle size.

```typescript
// Import only session management
import { createSession, validateSession } from '@amtarc-auth-utils/core/session';

// Or import everything
import * as auth from '@amtarc-auth-utils/core';
```

### 3. Type-Safe by Default

Built with TypeScript's strictest settings. Generic types allow you to extend with your own user and session types.

```typescript
interface MyUser extends User {
  email: string;
  roles: string[];
}

const session = createSession<MyUser>('user-123');
// session.user is typed as MyUser | undefined
```

### 4. Security-First

Safe defaults, explicit overrides. All security-sensitive features require conscious opt-in for less secure options.

### 5. Production-Ready

Features like caching, performance monitoring, and graceful error handling are built-in, not afterthoughts.

## Core Packages

### @amtarc-auth-utils/core

Session management, guards, cookie utilities, and error handling.

**Use for:** Session lifecycle, route protection, session validation

### @amtarc-auth-utils/security

CSRF protection, rate limiting, security headers, and encryption helpers.

**Use for:** API security, brute-force prevention, compliance requirements

### @amtarc-auth-utils/authorization

RBAC, ABAC, resource permissions, and policy evaluation.

**Use for:** Complex permission systems, multi-role applications

### @amtarc-auth-utils/tokens

JWT utilities, token validation, and refresh token patterns.

**Use for:** Token-based authentication, API key management

### @amtarc-auth-utils/multi-tenancy

Tenant context, isolation, and switching.

**Use for:** SaaS applications, multi-customer platforms

### @amtarc-auth-utils/audit

Audit logging, compliance helpers, and security event tracking.

**Use for:** GDPR compliance, SOC 2 audits, security monitoring

## Next Steps

- [Installation →](/guide/installation)
- [Quick Start →](/guide/quick-start)
- [API Reference →](/api/)
