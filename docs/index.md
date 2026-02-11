---
layout: home
hero:
  name: amtarc-auth-utils
  text: Enterprise Authentication Utilities
  tagline: Production-ready, type-safe authentication and authorization utilities for TypeScript
  actions:
    - theme: brand
      text: Get Started
      link: /guide/introduction
    - theme: alt
      text: View on GitHub
      link: https://github.com/amtarc/amtarc-auth-utils

features:
  - icon: 🔒
    title: Security First
    details: Built with security best practices and safe defaults
  
  - icon: 📦
    title: Modular Design
    details: Use only what you need with tree-shakable exports
  
  - icon: 🎯
    title: Type Safe
    details: Full TypeScript support with comprehensive type definitions
  
  - icon: 🚀
    title: Framework Agnostic
    details: Works with Express, Next.js, Fastify, and more
  
  - icon: 🏢
    title: Enterprise Ready
    details: Multi-tenancy, audit logging, and compliance features
  
  - icon: ⚡
    title: High Performance
    details: Optimized for production with caching and minimal overhead
---

## Quick Start

```bash
pnpm add @amtarc-auth-utils/core
```

```typescript
import { createSession, requireSession } from '@amtarc-auth-utils/core';

// Create a session
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
});

// Protect a route
const guard = requireSession(getSession);
const handler = guard(async (session) => {
  return { user: session.user };
});
```

## Why amtarc-auth-utils?

While authentication frameworks like Auth.js and Better Auth handle the core authentication flow, `amtarc-auth-utils` provides the **enterprise-grade utilities** you need to build production applications:

- **Advanced Session Management** - Multi-device sessions, fingerprinting, and rotation
- **Flexible Authorization** - RBAC, ABAC, and resource-based permissions
- **Security Utilities** - CSRF protection, rate limiting, and security headers
- **Multi-Tenancy Support** - Built-in tenant isolation and context management
- **Audit & Compliance** - GDPR and SOC 2 compliance helpers
- **Production Observability** - Metrics, tracing, and structured logging

## Packages

- **[@amtarc-auth-utils/core](./api/core)** - Session management and guards
- **[@amtarc-auth-utils/security](./api/security)** - CSRF, rate limiting, headers
- **[@amtarc-auth-utils/authorization](./api/authorization)** - RBAC, ABAC, permissions
- **[@amtarc-auth-utils/tokens](./api/tokens)** - JWT utilities and token management
- **[@amtarc-auth-utils/multi-tenancy](./api/multi-tenancy)** - Multi-tenant utilities
- **[@amtarc-auth-utils/audit](./api/audit)** - Audit logging and compliance
- **[@amtarc-auth-utils/testing](./api/testing)** - Testing utilities and mocks

## Framework Support

Official adapters for popular frameworks:

- Express
- Next.js (App Router & Pages Router)
- Fastify
- Hono

The core packages are framework-agnostic and can be used anywhere.
