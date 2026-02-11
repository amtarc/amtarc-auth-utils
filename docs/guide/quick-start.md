# Quick Start

This guide will get you up and running with `amtarc-auth-utils` in minutes.

## Basic Session Management

```typescript
import { createSession, validateSession } from '@amtarc-auth-utils/core';

// 1. Create a session after user authenticates
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  idleTimeout: 1000 * 60 * 30,    // 30 minutes
});

console.log(session);
// {
//   id: 'session_...',
//   userId: 'user-123',
//   expiresAt: Date,
//   createdAt: Date,
//   lastActivityAt: Date
// }

// 2. Validate a session
const validation = validateSession(session, {
  idleTimeout: 1000 * 60 * 30,
});

if (!validation.valid) {
  console.error('Session invalid:', validation.reason);
}

if (validation.shouldRefresh) {
  // Session is >50% through its lifetime
  // Consider refreshing it
}
```

## Using Guards

```typescript
import { requireSession } from '@amtarc-auth-utils/core';

// Define how to get the current session
async function getCurrentSession() {
  // Your logic to retrieve session from cookies, headers, etc.
  return session;
}

// Create a guard
const guard = requireSession(getCurrentSession, {
  idleTimeout: 1000 * 60 * 30,
});

// Protect your handlers
const protectedHandler = guard(async (session) => {
  // session is guaranteed to be valid here
  return {
    message: `Hello, user ${session.userId}!`,
    user: session.user,
  };
});

// Use the handler
try {
  const result = await protectedHandler();
  console.log(result);
} catch (error) {
  if (error instanceof SessionExpiredError) {
    // Redirect to login
  }
}
```

## With Express

```typescript
import express from 'express';
import { requireSession } from '@amtarc-auth-utils/core';

const app = express();

// Middleware to get session from request
function getSessionFromRequest(req: express.Request) {
  // Your session retrieval logic
  return req.session;
}

// Protected route
app.get('/api/profile', async (req, res) => {
  const guard = requireSession(() => getSessionFromRequest(req));
  
  const handler = guard(async (session) => {
    return { userId: session.userId };
  });
  
  try {
    const result = await handler();
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
});
```

## With Next.js App Router

```typescript
// app/api/profile/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { requireSession } from '@amtarc-auth-utils/core';
import { getSessionFromCookie } from '@/lib/auth';

export async function GET(request: NextRequest) {
  const guard = requireSession(() => getSessionFromCookie(request));
  
  const handler = guard(async (session) => {
    return { userId: session.userId };
  });
  
  try {
    const result = await handler();
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }
}
```

## Custom User Type

```typescript
import { User, Session, createSession } from '@amtarc-auth-utils/core';

// Extend the base User type
interface MyUser extends User {
  email: string;
  roles: string[];
  tenantId: string;
}

// Create a session with your user type
const session = createSession<MyUser>('user-123', {
  expiresIn: 1000 * 60 * 60 * 24,
});

// Add user data
session.user = {
  id: 'user-123',
  email: 'user@example.com',
  roles: ['admin', 'editor'],
  tenantId: 'tenant-1',
};

// Session is now fully typed
const userEmail = session.user?.email; // string | undefined
```

## Error Handling

```typescript
import {
  SessionExpiredError,
  AuthenticationError,
  AuthorizationError,
} from '@amtarc-auth-utils/core';

try {
  const result = await protectedHandler();
} catch (error) {
  if (error instanceof SessionExpiredError) {
    // Redirect to login
    res.redirect('/login');
  } else if (error instanceof AuthorizationError) {
    // User is authenticated but not authorized
    res.status(403).json({ error: 'Forbidden' });
  } else {
    // Other errors
    res.status(500).json({ error: 'Internal server error' });
  }
}
```

## Next Steps

- [Session Management in Depth →](/guide/sessions)
- [Guards & Middleware →](/guide/guards)
- [Error Handling →](/guide/errors)
- [API Reference →](/api/core)
