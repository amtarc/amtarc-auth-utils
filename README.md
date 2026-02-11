# amtarc-auth-utils

> Enterprise-grade authentication and authorization utilities for TypeScript

[![CI](https://github.com/amtarc/amtarc-auth-utils/workflows/CI/badge.svg)](https://github.com/amtarc/amtarc-auth-utils/actions)
[![npm version](https://img.shields.io/npm/v/@amtarc-auth-utils/core.svg)](https://www.npmjs.com/package/@amtarc-auth-utils/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## 🚀 Features

- 🔒 **Security First** - Built with security best practices and safe defaults
- 📦 **Modular Design** - Use only what you need with tree-shakable exports
- 🎯 **Type Safe** - Full TypeScript support with comprehensive type definitions
- 🚀 **Framework Agnostic** - Works with Express, Next.js, Fastify, and more
- 🏢 **Enterprise Ready** - Multi-tenancy, audit logging, and compliance features
- ⚡ **High Performance** - Optimized for production with caching and minimal overhead

## 📦 Packages

- [`@amtarc-auth-utils/core`](./packages/core) - Core authentication and session management
- [`@amtarc-auth-utils/security`](./packages/security) - CSRF, rate limiting, and security headers
- [`@amtarc-auth-utils/authorization`](./packages/authorization) - RBAC, ABAC, and permission systems
- [`@amtarc-auth-utils/tokens`](./packages/tokens) - JWT utilities and token management
- [`@amtarc-auth-utils/multi-tenancy`](./packages/multi-tenancy) - Multi-tenant utilities
- [`@amtarc-auth-utils/audit`](./packages/audit) - Audit logging and compliance
- [`@amtarc-auth-utils/testing`](./packages/testing) - Testing utilities and mocks
- [`@amtarc-auth-utils/observability`](./packages/observability) - Metrics and monitoring

## 🏃 Quick Start

```bash
pnpm add @amtarc-auth-utils/core
```

```typescript
import { createSession, requireSession } from '@amtarc-auth-utils/core';

// Create a session
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
});

// Protect a route (framework-agnostic)
const handler = requireSession(async (req, session) => {
  return { user: session.user };
});
```

## 📚 Documentation

Visit [https://amtarc-auth-utils.dev](https://amtarc-auth-utils.dev) for full documentation.

## 🛠️ Development

This project uses a monorepo structure with pnpm workspaces and Turborepo.

### Setup

```bash
# Install dependencies
pnpm install

# Build all packages
pnpm build

# Run tests
pnpm test

# Run linting
pnpm lint
```

### Project Structure

```
amtarc-auth-utils/
├── packages/
│   ├── core/                   # Core utilities
│   ├── security/              # Security utilities
│   ├── authorization/         # Authorization utilities
│   ├── tokens/               # Token management
│   ├── multi-tenancy/        # Multi-tenant utilities
│   ├── audit/                # Audit logging
│   ├── testing/              # Testing utilities
│   └── observability/        # Monitoring
├── examples/
│   ├── nextjs-app/           # Next.js example
│   ├── express-api/          # Express example
│   └── saas-starter/         # SaaS starter
└── docs/                     # Documentation
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## 📄 License

MIT © [amtarc](https://github.com/amtarc)

## 🙏 Acknowledgments

Built with the needs of modern enterprise applications in mind.
