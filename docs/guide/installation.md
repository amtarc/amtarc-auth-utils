# Installation

## Prerequisites

- Node.js 18.0 or higher
- TypeScript 5.0 or higher
- pnpm, npm, or yarn

## Install Core Package

```bash
# pnpm (recommended)
pnpm add @amtarc-auth-utils/core

# npm
npm install @amtarc-auth-utils/core

# yarn
yarn add @amtarc-auth-utils/core
```

## Install Additional Packages

Install only the packages you need:

```bash
# Security utilities
pnpm add @amtarc-auth-utils/security

# Authorization (RBAC, ABAC)
pnpm add @amtarc-auth-utils/authorization

# Token management
pnpm add @amtarc-auth-utils/tokens

# Multi-tenancy
pnpm add @amtarc-auth-utils/multi-tenancy

# Audit logging
pnpm add @amtarc-auth-utils/audit

# Testing utilities
pnpm add -D @amtarc-auth-utils/testing
```

## Framework Adapters

If you're using a specific framework, install the corresponding adapter:

```bash
# Express
pnpm add @amtarc-auth-utils/adapters-express

# Next.js
pnpm add @amtarc-auth-utils/adapters-nextjs

# Fastify
pnpm add @amtarc-auth-utils/adapters-fastify

# Hono
pnpm add @amtarc-auth-utils/adapters-hono
```

## TypeScript Configuration

Ensure your `tsconfig.json` has strict mode enabled for best results:

```json
{
  "compilerOptions": {
    "strict": true,
    "moduleResolution": "bundler",
    "esModuleInterop": true
  }
}
```

## Next Steps

- [Quick Start →](/guide/quick-start)
- [Session Management →](/guide/sessions)
