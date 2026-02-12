# Quick Start

This guide will get you up and running with `@amtarc/auth-utils` in minutes.

## Basic Session Management

```typescript
import { createSession, validateSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

// Setup storage
const storage = new MemoryStorageAdapter();

// 1. Create a session after user authenticates
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  idleTimeout: 1000 * 60 * 30,    // 30 minutes
});

// Store the session
await storage.set(session.sessionId, session);

console.log(session);
// {
//   sessionId: 'sess_...',
//   userId: 'user-123',
//   expiresAt: 1234567890,
//   createdAt: 1234567890,
//   lastActivityAt: 1234567890
// }

// 2. Validate a session
const validation = validateSession(session);

if (!validation.valid) {
  console.error('Session invalid:', validation.reason);
  // Reasons: 'expired', 'idle-timeout', 'absolute-timeout'
}

if (validation.shouldRefresh) {
  // Session is >50% through its lifetime - consider refreshing
  const refreshed = await refreshSession(session, storage);
}
```

## Route Protection with Guards

```typescript
import { requireAuth } from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

// Protect a route handler
const protectedHandler = requireAuth({
  storage,
  getSessionId: async (context) => {
    // Extract session ID from cookies or headers
    return context.request?.cookies?.session;
  },
  onSuccess: async (context) => {
    // This runs only if user is authenticated
    return {
      message: `Hello, user ${context.session.userId}!`,
      session: context.session
    };
  },
  onFailure: async (context) => {
    // This runs if authentication fails
    return {
      error: 'Unauthorized',
      redirect: '/login'
    };
  }
});

// Use the guard
const result = await protectedHandler({ request: { cookies: { session: 'sess_...' } } });
```

## With Express

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { createSession } from '@amtarc/auth-utils';
import { createAuthCookie, parseAuthCookies } from '@amtarc/auth-utils/cookies';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const app = express();
app.use(cookieParser());

const storage = new MemoryStorageAdapter();

// Login endpoint
app.post('/login', async (req, res) => {
  // Authenticate user (verify credentials, etc.)
  const userId = 'user-123';
  
  // Create session
  const session = createSession(userId, {
    expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  });
  
  await storage.set(session.sessionId, session);
  
  // Create secure cookie
  const cookie = createAuthCookie('session', session.sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 // 1 day in seconds
  });
  
  res.setHeader('Set-Cookie', cookie);
  res.json({ success: true });
});

// Protected route
const profileGuard = requireAuth({
  storage,
  getSessionId: async (context) => context.request.cookies?.session,
  onSuccess: async (context) => ({
    userId: context.session.userId,
    sessionId: context.session.sessionId
  }),
  onFailure: async () => ({ error: 'Unauthorized' })
});

app.get('/api/profile', async (req, res) => {
  try {
    const result = await profileGuard({ request: req });
    res.json(result);
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
});
```

## With Next.js App Router

```typescript
// app/actions/auth.ts
'use server';

import { cookies } from 'next/headers';
import { createSession } from '@amtarc/auth-utils';
import { createAuthCookie } from '@amtarc/auth-utils/cookies';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

export async function login(userId: string) {
  const session = createSession(userId, {
    expiresIn: 1000 * 60 * 60 * 24
  });
  
  await storage.set(session.sessionId, session);
  
  cookies().set('session', session.sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24
  });
  
  return { success: true };
}

// app/api/profile/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

export async function GET(request: NextRequest) {
  const guard = requireAuth({
    storage,
    getSessionId: async () => request.cookies.get('session')?.value,
    onSuccess: async (context) => ({
      userId: context.session.userId
    }),
    onFailure: async () => ({ error: 'Unauthorized' })
  });
  
  try {
    const result = await guard({ request });
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
}
```

## Signed Cookies

```typescript
import { createAuthCookie, signCookie, unsignCookie } from '@amtarc/auth-utils/cookies';

const SECRET = 'your-secret-key-min-32-chars';

// Create and sign a cookie
const cookie = createAuthCookie('session', session.sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});

const signed = signCookie(cookie, SECRET);
// Set-Cookie: session=sess_123.signature; HttpOnly; Secure; SameSite=Strict

// Verify and unsign cookie
const cookieHeader = req.headers.cookie;
const verified = unsignCookie(cookieHeader, 'session', SECRET);

if (verified.valid) {
  console.log('Session ID:', verified.value);
} else {
  console.error('Invalid cookie signature');
}
```

## Encrypted Cookies

```typescript
import { createAuthCookie, encryptCookie, decryptCookie } from '@amtarc/auth-utils/cookies';

const SECRET = 'your-secret-key-min-32-chars';

// Create and encrypt a cookie
const cookie = createAuthCookie('session', session.sessionId, {
  httpOnly: true,
  secure: true
});

const encrypted = await encryptCookie(cookie, SECRET);
// Value is encrypted with AES-256-GCM

// Decrypt cookie
const cookieHeader = req.headers.cookie;
const decrypted = await decryptCookie(cookieHeader, 'session', SECRET);

if (decrypted.valid) {
  console.log('Session ID:', decrypted.value);
} else {
  console.error('Failed to decrypt cookie');
}
```

## Custom Session Data

```typescript
interface UserData {
  email: string;
  roles: string[];
  tenantId: string;
}

// Create a session with custom data
const session = createSession<UserData>('user-123', {
  expiresIn: 1000 * 60 * 60 * 24,
  data: {
    email: 'user@example.com',
    roles: ['admin', 'editor'],
    tenantId: 'tenant-1'
  }
});

// Session is fully typed
const email = session.data?.email; // string | undefined
const roles = session.data?.roles; // string[] | undefined
```

## Multi-Device Sessions

```typescript
import { 
  addDeviceSession, 
  getActiveDevices, 
  revokeDevice 
} from '@amtarc/auth-utils/session';

// Add a device session
const device = await addDeviceSession(
  storage,
  'user-123',
  session.sessionId,
  {
    userAgent: 'Mozilla/5.0...',
    ip: '192.168.1.1'
  },
  { maxDevices: 5 } // Limit to 5 devices
);

// Get all active devices for a user
const devices = await getActiveDevices(storage, 'user-123');
console.log(`User has ${devices.length} active devices`);

// Revoke a specific device
await revokeDevice(storage, 'user-123', device.deviceId);
```

## Error Handling

```typescript
import {
  SessionExpiredError,
  UnauthenticatedError,
  InvalidCookieError,
  isAuthError,
  isSessionError
} from '@amtarc/auth-utils/errors';

try {
  const result = await protectedHandler();
} catch (error) {
  if (error instanceof SessionExpiredError) {
    // Session has expired
    res.redirect('/login');
  } else if (error instanceof UnauthenticatedError) {
    // User not authenticated
    res.status(401).json({ error: 'Unauthorized' });
  } else if (isSessionError(error)) {
    // Any session-related error
    res.status(401).json({ error: error.message });
  } else if (isAuthError(error)) {
    // Any authentication error
    res.status(error.statusCode || 401).json({ 
      error: error.message 
    });
  } else {
    // Other errors
    res.status(500).json({ error: 'Internal server error' });
  }
}
```

## Composable Guards

```typescript
import { 
  requireAuth, 
  requireGuest,
  requireAny,
  requireAll,
  conditionalGuard
} from '@amtarc/auth-utils/guards';

// Require either authenticated OR guest (always allow)
const publicGuard = requireAny([
  requireAuth({ storage, getSessionId, onSuccess, onFailure }),
  requireGuest({ onSuccess })
]);

// Require both conditions (AND logic)
const strictGuard = requireAll([
  requireAuth({ storage, getSessionId, onSuccess, onFailure }),
  customRoleCheck
]);

// Conditional guard based on runtime logic
const dynamicGuard = conditionalGuard({
  condition: async (context) => context.request?.path === '/admin',
  guardIfTrue: adminGuard,
  guardIfFalse: userGuard
});
```

## Next Steps

- [Session Management](/guide/sessions) - Complete session features
- [Guards](/guide/guards) - Advanced route protection
- [Cookies](/guide/cookies) - Secure cookie handling
- [Error Handling](/guide/errors) - Comprehensive error handling
- [API Reference](/api/core) - Complete API documentation
