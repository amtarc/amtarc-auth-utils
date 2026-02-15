# @amtarc/auth-utils

> Enterprise-grade authentication and authorization utilities for TypeScript

[![CI](https://github.com/amtarc/amtarc-auth-utils/workflows/CI/badge.svg)](https://github.com/amtarc/amtarc-auth-utils/actions)
[![npm version](https://img.shields.io/npm/v/@amtarc/auth-utils.svg)](https://www.npmjs.com/package/@amtarc/auth-utils)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Security First** - Built with security best practices and safe defaults
- **Modular Design** - Use only what you need with tree-shakable exports
- **Type Safe** - Full TypeScript support with comprehensive type definitions
- **Framework Agnostic** - Works with Express, Next.js, Fastify, and more
- **Enterprise Ready** - Multi-device sessions, audit logging, and compliance features
- **High Performance** - Optimized for production with minimal overhead (~4.4KB)

## Packages

### Core Package (v1.3.0 - Available)
**[`@amtarc/auth-utils`](./packages/core)** 

**Session Management:**
- Session creation, validation, and refresh
- Multi-device session support with tracking
- Session fingerprinting for device identification
- Storage adapter pattern (Memory + custom)
- Session ID rotation for security
- Concurrent session limits

**Guards & Route Protection:**
- Authentication guards (`requireAuth`, `requireGuest`)
- Composable guard system (`requireAny`, `requireAll`)
- Redirect management with open redirect prevention
- Framework-agnostic design

**Cookie Management:**
- Secure cookie creation and parsing (RFC 6265 compliant)
- HMAC cookie signing (SHA-256)
- AES-256-GCM cookie encryption
- Cookie rotation and deletion utilities
- Secure defaults (HttpOnly, Secure, SameSite)

**Security (Phase 3 - v1.2.0):**
- CSRF protection (double-submit & synchronizer patterns)
- Rate limiting (token bucket, fixed window, sliding window algorithms)
- Brute-force protection with progressive delays and lockout
- Security headers builder (CSP, HSTS, CORS, etc.)
- AES-256-GCM encryption with key derivation (PBKDF2/Scrypt)
- Secure random generation (tokens, UUIDs, strings)
- Universal storage adapter for all modules

**Authorization (Phase 4 - v1.3.0):**
- RBAC (Role-Based Access Control) with permission inheritance
- Role hierarchy with parent/child relationships
- Scoped role assignments (multi-tenant, organization, team)
- Permission and role management with CRUD operations
- User-role assignments with expiration support
- Authorization guards (`requirePermission`, `requireRole`)
- Functional API (no class instantiation required)
- Memory storage adapter + custom adapter support

**Error Handling:**
- 25+ specialized error classes with HTTP status codes
- Type guards for error classification
- JSON serialization for API responses
- Operational vs programmer error distinction

### Future Packages (In Development)
- [`@amtarc/auth-utils-authorization`](./packages/authorization) - RBAC, ABAC, and permission systems
- [`@amtarc/auth-utils-tokens`](./packages/tokens) - JWT utilities and token management
- [`@amtarc/auth-utils-multi-tenancy`](./packages/multi-tenancy) - Multi-tenant utilities
- [`@amtarc/auth-utils-audit`](./packages/audit) - Audit logging and compliance
- [`@amtarc/auth-utils-testing`](./packages/testing) - Testing utilities and mocks
- [`@amtarc/auth-utils-observability`](./packages/observability) - Metrics and monitoring


## Documentation

Visit [https://amtarc-auth-utils.dev](https://amtarc-auth-utils.dev) for full documentation.

**Quick Links:**
- [Installation Guide](https://amtarc-auth-utils.dev/guide/installation)
- [API Reference](https://amtarc-auth-utils.dev/api/core)
- [Framework Integration](https://amtarc-auth-utils.dev/guide/frameworks)
- [Examples](./examples)

## Why @amtarc/auth-utils?

Unlike full authentication frameworks, `@amtarc/auth-utils` provides **focused utilities** that complement your existing auth solution:

| Feature | @amtarc/auth-utils | Full Auth Frameworks |
|---------|-------------------|---------------------|
| **Purpose** | Security utilities | Complete auth flow |
| **Flexibility** | Mix & match modules | All-in-one solution |
| **Bundle Size** | ~12KB (tree-shakeable) | Often 50KB+ |
| **CSRF Protection** | Built-in | Varies |
| **Rate Limiting** | 4 algorithms | Often missing |
| **Encryption** | AES-256-GCM | Varies |
| **RBAC Authorization** | Built-in | Varies |
| **Role Hierarchy** | Built-in | Often missing |
| **Permission System** | Granular | Varies |
| **Framework Support** | Truly agnostic | Framework-specific |
| **Multi-device Sessions** | Built-in | Often missing |
| **Session Fingerprinting** | Built-in | Often missing |
| **Cookie Encryption** | Built-in | Varies |
| **Error Handling** | HTTP-aware errors | Generic errors |

Perfect for:
- Adding advanced session management to existing auth setups
- Building custom authentication flows
- Enhancing Auth.js, Better Auth, or Clerk with utilities
- Serverless and edge environments
- Microservices architectures

## Development

This project uses a monorepo structure with pnpm workspaces and Turborepo.

### Setup

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests (661 tests, >95% coverage)
pnpm test

# Run linting
pnpm lint
```


## Stats

**Core Package (v1.3.0):**
- Bundle Size: ~12 KB (gzipped, tree-shakeable)
- Tests: 661 passing (100% pass rate)
- Coverage: >95%
- TypeScript: Strict mode + exactOptionalPropertyTypes
- Build Time: <1s (ESM + CJS + DTS)
- Zero runtime dependencies (Node.js crypto only)

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## License

MIT © [amtarc](https://github.com/amtarc)

## Acknowledgments

Built with the needs of modern enterprise applications in mind.
