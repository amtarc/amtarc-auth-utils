# Installation

## Prerequisites

- Node.js 16.0 or higher
- TypeScript 5.0 or higher (recommended)
- npm, pnpm, or yarn

## Install the Package

```bash
# pnpm (recommended)
pnpm add @amtarc/auth-utils

# npm
npm install @amtarc/auth-utils

# yarn
yarn add @amtarc/auth-utils
```

## Verify Installation

Create a simple session to verify the installation:

```typescript
import { createSession } from '@amtarc/auth-utils';

const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60, // 1 hour
});

console.log('Session created:', session.sessionId);
```

## TypeScript Configuration

For the best experience, configure TypeScript with strict mode:

```json
{
  "compilerOptions": {
    "strict": true,
    "moduleResolution": "bundler",
    "esModuleInterop": true,
    "skipLibCheck": true
  }
}
```

## Import Paths

The package provides multiple entry points for tree-shaking:

```typescript
// Main exports (core functionality)
import { createSession, requireAuth } from '@amtarc/auth-utils';

// Session module
import { 
  createSession, 
  refreshSession,
  invalidateSession 
} from '@amtarc/auth-utils/session';

// Guards module
import { 
  requireAuth, 
  requireGuest,
  requireAny 
} from '@amtarc/auth-utils/guards';

// Cookies module
import { 
  createAuthCookie, 
  parseAuthCookies,
  getAuthCookie,
  signCookie,
  encryptCookie 
} from '@amtarc/auth-utils/cookies';

// Errors module
import { 
  UnauthenticatedError,
  SessionExpiredError,
  isAuthError 
} from '@amtarc/auth-utils/errors';
```

## Framework-Specific Setup

### Express

```typescript
import express from 'express';
import { createSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const app = express();
const storage = new MemoryStorageAdapter();

app.post('/login', async (req, res) => {
  // Authenticate user...
  const session = createSession('user-123');
  await storage.set(session.sessionId, session);
  
  res.cookie('session', session.sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });
  
  res.json({ success: true });
});
```

### Next.js (App Router)

```typescript
// app/actions/auth.ts
'use server';

import { cookies } from 'next/headers';
import { createSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

export async function login(userId: string) {
  const session = createSession(userId);
  await storage.set(session.sessionId, session);
  
  cookies().set('session', session.sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 // 1 day
  });
  
  return { success: true };
}
```

### Fastify

```typescript
import Fastify from 'fastify';
import { createSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const fastify = Fastify();
const storage = new MemoryStorageAdapter();

fastify.post('/login', async (request, reply) => {
  // Authenticate user...
  const session = createSession('user-123');
  await storage.set(session.sessionId, session);
  
  reply
    .setCookie('session', session.sessionId, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict'
    })
    .send({ success: true });
});
```

## Bundle Size

The library is designed to be tree-shakeable. Only import what you need:

| Import | Size (gzipped) |
|--------|----------------|
| Full package | ~4.4KB |
| Session only | ~2.1KB |
| Guards only | ~1.2KB |
| Cookies only | ~1.8KB |
| Errors only | ~0.8KB |

## Next Steps

- [Quick Start](/guide/quick-start) - Build your first protected route
- [Session Management](/guide/sessions) - Learn about session features
- [Guards](/guide/guards) - Protect your routes
- [Cookies](/guide/cookies) - Secure cookie handling
