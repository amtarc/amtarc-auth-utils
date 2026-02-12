# Guards & Route Protection

Complete guide to protecting routes with authentication guards, composition, and redirect handling.

## Overview

Guards provide declarative route protection with:

- `requireAuth` - Require authenticated users
- `requireGuest` - Require unauthenticated users
- `requireAny` - OR logic for multiple guards
- `requireAll` - AND logic for multiple guards
- `chainGuards` - Sequential guard execution
- `allowAll` - Always allow access
- `conditionalGuard` - Dynamic guard selection
- Redirect management with open redirect prevention

## Basic Authentication Guard

### Simple requireAuth

```typescript
import { requireAuth } from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

const protectedHandler = requireAuth({
  storage,
  getSessionId: async (context) => {
    // Extract session ID from cookies, headers, etc.
    return context.request?.cookies?.session;
  },
  onSuccess: async (context) => {
    // Runs when user is authenticated
    return {
      message: `Welcome, user ${context.session.userId}`,
      data: context.session.data
    };
  },
  onFailure: async (context) => {
    // Runs when authentication fails
    return {
      error: 'Unauthorized',
      redirect: '/login'
    };
  }
});

// Use the guard
const result = await protectedHandler({ 
  request: { cookies: { session: 'sess_123' } } 
});
```

### With Redirect

```typescript
import { requireAuth, redirect } from '@amtarc/auth-utils/guards';

const protectedHandler = requireAuth({
  storage,
  getSessionId: async (context) => context.request?.cookies?.session,
  onSuccess: async (context) => ({
    userId: context.session.userId
  }),
  onFailure: async (context) => {
    // Redirect to login with return URL
    return redirect('/login', {
      query: { returnUrl: context.request?.url }
    });
  }
});
```

### Open Redirect Prevention

```typescript
import { requireAuth, redirect } from '@amtarc/auth-utils/guards';

const protectedHandler = requireAuth({
  storage,
  getSessionId: async (context) => context.request?.cookies?.session,
  onSuccess: async (context) => ({ success: true }),
  onFailure: async (context) => {
    const returnUrl = context.request?.query?.returnUrl;
    
    // Validate redirect URL to prevent open redirects
    return redirect('/login', {
      query: { returnUrl },
      allowedDomains: ['example.com', 'app.example.com'],
      allowRelative: true // Allow relative paths like /dashboard
    });
  }
});
```

## Guest Guard

Require unauthenticated users (for login/register pages):

```typescript
import { requireGuest } from '@amtarc/auth-utils/guards';

const loginPageGuard = requireGuest({
  onSuccess: async (context) => {
    // User is not authenticated - show login page
    return { showLogin: true };
  },
  onFailure: async (context) => {
    // User is already authenticated - redirect to dashboard
    return redirect('/dashboard');
  },
  storage,
  getSessionId: async (context) => context.request?.cookies?.session
});
```

## Composable Guards

### requireAny (OR Logic)

Require at least one guard to pass:

```typescript
import { requireAny, requireAuth, allowAll } from '@amtarc/auth-utils/guards';

// Allow authenticated users OR public access
const publicOrAuthGuard = requireAny([
  requireAuth({
    storage,
    getSessionId: async (context) => context.request?.cookies?.session,
    onSuccess: async (context) => ({ 
      user: context.session.userId,
      authenticated: true 
    }),
    onFailure: async () => ({ authenticated: false })
  }),
  allowAll({
    onSuccess: async () => ({ authenticated: false, public: true })
  })
]);
```

### requireAll (AND Logic)

Require all guards to pass:

```typescript
import { requireAll, requireAuth } from '@amtarc/auth-utils/guards';

// Custom role check guard
function requireRole(role: string) {
  return async (context: GuardContext) => {
    const roles = context.session?.data?.roles || [];
    if (!roles.includes(role)) {
      throw new Error(`Missing required role: ${role}`);
    }
    return { success: true };
  };
}

// Require authentication AND admin role
const adminGuard = requireAll([
  requireAuth({
    storage,
    getSessionId: async (context) => context.request?.cookies?.session,
    onSuccess: async (context) => context,
    onFailure: async () => redirect('/login')
  }),
  requireRole('admin')
]);
```

### chainGuards (Sequential)

Execute guards in sequence:

```typescript
import { chainGuards, requireAuth } from '@amtarc/auth-utils/guards';

// Check authentication, then check specific permission
const permissionGuard = chainGuards([
  requireAuth({
    storage,
    getSessionId: async (context) => context.request?.cookies?.session,
    onSuccess: async (context) => context,
    onFailure: async () => redirect('/login')
  }),
  async (context) => {
    // Custom permission check
    const hasPermission = await checkPermission(
      context.session.userId,
      context.request?.resource
    );
    if (!hasPermission) {
      return redirect('/forbidden');
    }
    return { allowed: true };
  }
]);
```

### conditionalGuard (Dynamic)

Choose guard based on runtime condition:

```typescript
import { conditionalGuard, requireAuth, requireGuest } from '@amtarc/auth-utils/guards';

const dynamicGuard = conditionalGuard({
  condition: async (context) => {
    // Check if route requires authentication
    return context.request?.path?.startsWith('/admin');
  },
  guardIfTrue: requireAuth({
    storage,
    getSessionId: async (context) => context.request?.cookies?.session,
    onSuccess: async (context) => ({ authenticated: true }),
    onFailure: async () => redirect('/login')
  }),
  guardIfFalse: allowAll({
    onSuccess: async () => ({ public: true })
  })
});
```

## Framework Integration

### Express

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const app = express();
app.use(cookieParser());

const storage = new MemoryStorageAdapter();

// Middleware wrapper
function authMiddleware() {
  const guard = requireAuth({
    storage,
    getSessionId: async (context) => context.request.cookies?.session,
    onSuccess: async (context) => context,
    onFailure: async () => {
      throw new Error('Unauthorized');
    }
  });

  return async (req: express.Request, res: express.Response, next: express.NextFunction) => {
    try {
      const result = await guard({ request: req });
      req.session = result.session; // Attach session to request
      next();
    } catch (error) {
      res.status(401).json({ error: 'Unauthorized' });
    }
  };
}

// Use middleware
app.get('/api/profile', authMiddleware(), (req, res) => {
  res.json({ userId: req.session.userId });
});
```

### Next.js App Router

```typescript
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
      userId: context.session.userId,
      data: context.session.data
    }),
    onFailure: async () => ({
      error: 'Unauthorized'
    })
  });

  try {
    const result = await guard({ request });
    return NextResponse.json(result);
  } catch (error) {
    return NextResponse.json(
      { error: 'Unauthorized' },
      { status: 401 }
    );
  }
}
```

### Next.js Middleware (Edge)

```typescript
// middleware.ts
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

export async function middleware(request: NextRequest) {
  // Only protect specific paths
  if (!request.nextUrl.pathname.startsWith('/dashboard')) {
    return NextResponse.next();
  }

  const guard = requireAuth({
    storage,
    getSessionId: async () => request.cookies.get('session')?.value,
    onSuccess: async () => ({ authenticated: true }),
    onFailure: async () => ({ authenticated: false })
  });

  try {
    await guard({ request });
    return NextResponse.next();
  } catch (error) {
    return NextResponse.redirect(new URL('/login', request.url));
  }
}

export const config = {
  matcher: '/dashboard/:path*'
};
```

### Fastify

```typescript
import Fastify from 'fastify';
import { requireAuth } from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const fastify = Fastify();
const storage = new MemoryStorageAdapter();

// Decorator for guards
fastify.decorateRequest('session', null);

// Auth hook
fastify.addHook('preHandler', async (request, reply) => {
  if (request.routerPath === '/api/profile') {
    const guard = requireAuth({
      storage,
      getSessionId: async () => request.cookies.session,
      onSuccess: async (context) => context,
      onFailure: async () => {
        throw new Error('Unauthorized');
      }
    });

    try {
      const result = await guard({ request });
      request.session = result.session;
    } catch (error) {
      reply.code(401).send({ error: 'Unauthorized' });
    }
  }
});

fastify.get('/api/profile', async (request, reply) => {
  return { userId: request.session.userId };
});
```

## Advanced Patterns

### Role-Based Access Control

```typescript
import { requireAll, requireAuth } from '@amtarc/auth-utils/guards';

function requireRoles(...requiredRoles: string[]) {
  return async (context: GuardContext) => {
    const userRoles = context.session?.data?.roles || [];
    const hasRole = requiredRoles.some(role => userRoles.includes(role));
    
    if (!hasRole) {
      throw new UnauthorizedError(
        `Required roles: ${requiredRoles.join(', ')}`
      );
    }
    
    return { success: true };
  };
}

// Require authentication AND admin or moderator role
const moderatedGuard = requireAll([
  requireAuth({ storage, getSessionId, onSuccess, onFailure }),
  requireRoles('admin', 'moderator')
]);
```

### Resource-Based Permissions

```typescript
import { chainGuards, requireAuth } from '@amtarc/auth-utils/guards';

function requireResourceAccess(resourceId: string) {
  return async (context: GuardContext) => {
    const hasAccess = await checkResourceAccess(
      context.session.userId,
      resourceId
    );
    
    if (!hasAccess) {
      throw new ForbiddenError('No access to this resource');
    }
    
    return { resource: resourceId };
  };
}

// Check auth, then check resource access
const resourceGuard = (resourceId: string) => chainGuards([
  requireAuth({ storage, getSessionId, onSuccess, onFailure }),
  requireResourceAccess(resourceId)
]);

// Usage
app.get('/api/documents/:id', async (req, res) => {
  const guard = resourceGuard(req.params.id);
  const result = await guard({ request: req });
  res.json(result);
});
```

### Time-Based Access

```typescript
import { conditionalGuard, requireAuth, allowAll } from '@amtarc/auth-utils/guards';

function isBusinessHours(): boolean {
  const hour = new Date().getHours();
  return hour >= 9 && hour < 17;
}

const businessHoursGuard = conditionalGuard({
  condition: async () => isBusinessHours(),
  guardIfTrue: allowAll({ onSuccess: async () => ({ allowed: true }) }),
  guardIfFalse: requireAuth({ 
    storage, 
    getSessionId,
    onSuccess: async (context) => ({
      userId: context.session.userId,
      afterHours: true
    }),
    onFailure: async () => ({
      error: 'System only available during business hours (9AM-5PM)'
    })
  })
});
```

### Multi-Factor Authentication

```typescript
import { chainGuards, requireAuth } from '@amtarc/auth-utils/guards';

function require2FA() {
  return async (context: GuardContext) => {
    const has2FA = context.session?.data?.twoFactorVerified;
    
    if (!has2FA) {
      return redirect('/verify-2fa', {
        query: { returnUrl: context.request?.url }
      });
    }
    
    return { verified: true };
  };
}

// Require authentication AND 2FA verification
const secure Guard = chainGuards([
  requireAuth({ storage, getSessionId, onSuccess, onFailure }),
  require2FA()
]);
```

## Complete Example

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import {
  requireAuth,
  requireGuest,
  requireAny,
  requireAll,
  allowAll,
  redirect
} from '@amtarc/auth-utils/guards';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const app = express();
app.use(cookieParser());

const storage = new MemoryStorageAdapter();

// Helper to create guards
const createAuthGuard = () => requireAuth({
  storage,
  getSessionId: async (context) => context.request?.cookies?.session,
  onSuccess: async (context) => context,
  onFailure: async (context) => redirect('/login', {
    query: { returnUrl: context.request?.url },
    allowRelative: true
  })
});

const createGuestGuard = () => requireGuest({
  storage,
  getSessionId: async (context) => context.request?.cookies?.session,
  onSuccess: async (context) => context,
  onFailure: async () => redirect('/dashboard')
});

// Public route (no guard needed)
app.get('/', (req, res) => res.json({ message: 'Home' }));

// Guest-only route (login page)
app.get('/login', async (req, res) => {
  const guard = createGuestGuard();
  try {
    await guard({ request: req });
    res.json({ showLogin: true });
  } catch (error) {
    res.redirect('/dashboard');
  }
});

// Protected route
app.get('/dashboard', async (req, res) => {
  const guard = createAuthGuard();
  try {
    const result = await guard({ request: req });
    res.json({ userId: result.session.userId });
  } catch (error) {
    res.redirect('/login');
  }
});

// Admin-only route
function requireRole(role: string) {
  return async (context: any) => {
    const roles = context.session?.data?.roles || [];
    if (!roles.includes(role)) {
      throw new Error('Forbidden');
    }
    return context;
  };
}

app.get('/admin', async (req, res) => {
  const guard = requireAll([
    createAuthGuard(),
    requireRole('admin')
  ]);
  
  try {
    const result = await guard({ request: req });
    res.json({ admin: true });
  } catch (error) {
    res.status(403).json({ error: 'Forbidden' });
  }
});

// Public OR authenticated route
app.get('/blog', async (req, res) => {
  const guard = requireAny([
    createAuthGuard(),
    allowAll({ onSuccess: async () => ({ public: true }) })
  ]);
  
  const result = await guard({ request: req });
  res.json({ 
    authenticated: !!result.session,
    posts: [] 
  });
});

app.listen(3000);
```

## Best Practices

1. **Use Composition**: Combine guards with `requireAll`, `requireAny` for complex logic
2. **Prevent Open Redirects**: Always validate redirect URLs with `allowedDomains`
3. **Separate Concerns**: Keep authentication separate from authorization logic
4. **Handle Errors Gracefully**: Provide clear error messages and redirect paths
5. **Cache Guard Results**: Avoid re-validating the same session multiple times per request
6. **Use Type Safety**: Leverage TypeScript generics for session data
7. **Test Guard Combinations**: Ensure composed guards work as expected
8. **Log Security Events**: Track failed authentication attempts

## Next Steps

- [Session Management](/guide/sessions) - Session creation and validation
- [Cookies](/guide/cookies) - Secure cookie handling for session IDs
- [Error Handling](/guide/errors) - Handle guard errors properly
- [API Reference](/api/core) - Complete API documentation
