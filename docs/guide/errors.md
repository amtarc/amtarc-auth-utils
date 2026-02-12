# Error Handling

Complete guide to handling authentication and session errors with type-safe error classes and HTTP status mapping.

## Overview

The error handling module provides:

- 17+ specialized error classes for authentication scenarios
- HTTP status code mapping for API responses
- Type guards for error classification
- JSON serialization support
- Error metadata and context
- Framework-agnostic error handling

## Error Categories

### Authentication Errors

Errors related to user authentication:

```typescript
import {
  UnauthenticatedError,
  InvalidCredentialsError,
  AccountLockedError,
  FingerprintMismatchError
} from '@amtarc/auth-utils/errors';

// User not authenticated
throw new UnauthenticatedError('Please log in');
// Status: 401

// Wrong credentials
throw new InvalidCredentialsError('Invalid email or password');
// Status: 401

// Account locked
throw new AccountLockedError('Account locked due to failed attempts');
// Status: 403

// Session fingerprint doesn't match
throw new FingerprintMismatchError('Session fingerprint mismatch');
// Status: 401
```

### Session Errors

Errors related to session lifecycle:

```typescript
import {
  SessionExpiredError,
  SessionNotFoundError,
  SessionRevokedError,
  ConcurrentSessionError,
  InvalidSessionError
} from '@amtarc/auth-utils/errors';

// Session has expired
throw new SessionExpiredError('Your session has expired');
// Status: 401

// Session not found in storage
throw new SessionNotFoundError('Session not found');
// Status: 401

// Session was revoked
throw new SessionRevokedError('Session has been revoked');
// Status: 401

// Too many concurrent sessions
throw new ConcurrentSessionError('Maximum device limit reached');
// Status: 429

// Session data is invalid
throw new InvalidSessionError('Session data is corrupted');
// Status: 400
```

### Cookie Errors

Errors related to cookie handling:

```typescript
import {
  InvalidCookieError,
  CookieSignatureMismatchError,
  CookieDecryptionError
} from '@amtarc/auth-utils/errors';

// Cookie format invalid
throw new InvalidCookieError('Invalid cookie format');
// Status: 400

// Cookie signature doesn't match
throw new CookieSignatureMismatchError('Cookie signature invalid');
// Status: 401

// Failed to decrypt cookie
throw new CookieDecryptionError('Failed to decrypt cookie');
// Status: 400
```

### Token Errors

Errors related to token handling:

```typescript
import {
  InvalidTokenError,
  TokenExpiredError,
  TokenRevokedError
} from '@amtarc/auth-utils/errors';

// Token format invalid
throw new InvalidTokenError('Invalid token format');
// Status: 401

// Token has expired
throw new TokenExpiredError('Token expired');
// Status: 401

// Token was revoked
throw new TokenRevokedError('Token has been revoked');
// Status: 401
```

### Validation Errors

Errors related to input validation:

```typescript
import { ValidationError } from '@amtarc/auth-utils/errors';

// Single field error
throw new ValidationError('Email is required', {
  field: 'email',
  value: ''
});
// Status: 400

// Multiple field errors
throw new ValidationError('Validation failed', {
  errors: [
    { field: 'email', message: 'Email is required' },
    { field: 'password', message: 'Password must be 8+ characters' }
  ]
});
// Status: 400
```

### Authorization Errors

Errors related to permissions:

```typescript
import { 
  UnauthorizedError,
  ForbiddenError,
  InsufficientPermissionsError
} from '@amtarc/auth-utils/errors';

// Generic authorization failure
throw new UnauthorizedError('Not authorized');
// Status: 403

// Specific resource forbidden
throw new ForbiddenError('Access to this resource is forbidden');
// Status: 403

// Missing required permission
throw new InsufficientPermissionsError('Missing required permission: admin');
// Status: 403
```

## Error Properties

All error classes extend the base `AuthError` class:

```typescript
class AuthError extends Error {
  /** Error code for identification */
  code: string;
  
  /** HTTP status code */
  statusCode: number;
  
  /** Additional error metadata */
  metadata?: Record<string, unknown>;
  
  /** Timestamp when error was created */
  timestamp: number;
}
```

### Accessing Error Properties

```typescript
try {
  throw new SessionExpiredError('Session expired');
} catch (error) {
  if (error instanceof AuthError) {
    console.log('Code:', error.code); // 'SESSION_EXPIRED'
    console.log('Status:', error.statusCode); // 401
    console.log('Message:', error.message); // 'Session expired'
    console.log('Timestamp:', error.timestamp); // 1234567890
  }
}
```

### Custom Metadata

```typescript
throw new ValidationError('Invalid input', {
  field: 'email',
  value: 'invalid-email',
  constraint: 'email format',
  customData: { userId: '123' }
});

// Access metadata
catch (error) {
  if (error instanceof ValidationError) {
    console.log(error.metadata.field); // 'email'
    console.log(error.metadata.value); // 'invalid-email'
  }
}
```

## Type Guards

Type guards for error classification:

### Authentication Type Guards

```typescript
import { 
  isAuthError,
  isAuthenticationError,
  isUnauthenticatedError
} from '@amtarc/auth-utils/errors';

try {
  // ... your code
} catch (error) {
  if (isAuthError(error)) {
    // Any error from this library
    console.log('Auth error:', error.code);
  }
  
  if (isAuthenticationError(error)) {
    // Authentication-related error
    // (UnauthenticatedError, InvalidCredentialsError, etc.)
    console.log('Authentication failed');
  }
  
  if (isUnauthenticatedError(error)) {
    // Specifically UnauthenticatedError
    console.log('User not authenticated');
  }
}
```

### Session Type Guards

```typescript
import {
  isSessionError,
  isSessionExpiredError,
  isSessionNotFoundError
} from '@amtarc/auth-utils/errors';

try {
  // ... your code
} catch (error) {
  if (isSessionError(error)) {
    // Any session-related error
    console.log('Session error:', error.message);
  }
  
  if (isSessionExpiredError(error)) {
    // Specifically SessionExpiredError
    console.log('Session expired, redirecting to login');
  }
  
  if (isSessionNotFoundError(error)) {
    // Specifically SessionNotFoundError
    console.log('Session not found in storage');
  }
}
```

### Cookie Type Guards

```typescript
import {
  isCookieError,
  isInvalidCookieError,
  isCookieSignatureMismatchError
} from '@amtarc/auth-utils/errors';

try {
  // ... your code
} catch (error) {
  if (isCookieError(error)) {
    // Any cookie-related error
    console.log('Cookie error:', error.code);
  }
  
  if (isInvalidCookieError(error)) {
    // Invalid cookie format
    console.log('Invalid cookie');
  }
  
  if (isCookieSignatureMismatchError(error)) {
    // Cookie signature doesn't match
    console.log('Cookie has been tampered with');
  }
}
```

### Validation Type Guards

```typescript
import { isValidationError } from '@amtarc/auth-utils/errors';

try {
  // ... your code
} catch (error) {
  if (isValidationError(error)) {
    // Validation error with field details
    const errors = error.metadata?.errors;
    console.log('Validation errors:', errors);
  }
}
```

## JSON Serialization

All errors support JSON serialization for API responses:

```typescript
try {
  throw new SessionExpiredError('Session expired');
} catch (error) {
  if (error instanceof AuthError) {
    const json = error.toJSON();
    
    console.log(json);
    // {
    //   code: 'SESSION_EXPIRED',
    //   message: 'Session expired',
    //   statusCode: 401,
    //   timestamp: 1234567890,
    //   metadata: {}
    // }
    
    // Send to client
    res.status(error.statusCode).json(json);
  }
}
```

## Framework Integration

### Express Error Handler

```typescript
import express from 'express';
import { AuthError, isAuthError } from '@amtarc/auth-utils/errors';

const app = express();

// Error handling middleware
app.use((err, req, res, next) => {
  if (isAuthError(err)) {
    return res.status(err.statusCode).json(err.toJSON());
  }
  
  // Handle other errors
  res.status(500).json({
    error: 'Internal server error',
    message: err.message
  });
});

// Route with error
app.get('/api/profile', async (req, res, next) => {
  try {
    if (!req.session) {
      throw new UnauthenticatedError('Please log in');
    }
    
    res.json({ user: req.session.userId });
  } catch (error) {
    next(error); // Pass to error handler
  }
});
```

### Next.js API Route

```typescript
// app/api/profile/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { 
  UnauthenticatedError,
  SessionExpiredError,
  isAuthError 
} from '@amtarc/auth-utils/errors';

export async function GET(request: NextRequest) {
  try {
    const session = await getSession(request);
    
    if (!session) {
      throw new UnauthenticatedError('Please log in');
    }
    
    // Validate session
    const validation = validateSession(session);
    if (!validation.valid) {
      throw new SessionExpiredError('Session expired');
    }
    
    return NextResponse.json({ userId: session.userId });
  } catch (error) {
    if (isAuthError(error)) {
      return NextResponse.json(
        error.toJSON(),
        { status: error.statusCode }
      );
    }
    
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
```

### Fastify Error Handler

```typescript
import Fastify from 'fastify';
import { AuthError, isAuthError } from '@amtarc/auth-utils/errors';

const fastify = Fastify();

// Custom error handler
fastify.setErrorHandler((error, request, reply) => {
  if (isAuthError(error)) {
    return reply.code(error.statusCode).send(error.toJSON());
  }
  
  reply.code(500).send({
    error: 'Internal server error',
    message: error.message
  });
});

// Route
fastify.get('/api/profile', async (request, reply) => {
  if (!request.session) {
    throw new UnauthenticatedError('Please log in');
  }
  
  return { userId: request.session.userId };
});
```

## Complete Error Handling Example

```typescript
import express from 'express';
import {
  UnauthenticatedError,
  SessionExpiredError,
  InvalidCredentialsError,
  ValidationError,
  ForbiddenError,
  isAuthError,
  isSessionError,
  isValidationError
} from '@amtarc/auth-utils/errors';
import {
  createSession,
  validateSession,
  refreshSession
} from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const app = express();
app.use(express.json());

const storage = new MemoryStorageAdapter();

// Login with validation
app.post('/login', async (req, res, next) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      throw new ValidationError('Missing required fields', {
        errors: [
          !email && { field: 'email', message: 'Email is required' },
          !password && { field: 'password', message: 'Password is required' }
        ].filter(Boolean)
      });
    }
    
    // Authenticate
    const user = await authenticateUser(email, password);
    if (!user) {
      throw new InvalidCredentialsError('Invalid email or password');
    }
    
    // Create session
    const session = createSession(user.id, {
      expiresIn: 1000 * 60 * 60 * 24
    });
    
    await storage.set(session.sessionId, session);
    
    res.json({ 
      sessionId: session.sessionId,
      userId: user.id 
    });
  } catch (error) {
    next(error);
  }
});

// Protected route
app.get('/api/profile', async (req, res, next) => {
  try {
    const sessionId = req.headers.authorization?.split(' ')[1];
    
    if (!sessionId) {
      throw new UnauthenticatedError('No session provided');
    }
    
    const session = await storage.get(sessionId);
    
    if (!session) {
      throw new UnauthenticatedError('Session not found');
    }
    
    // Validate session
    const validation = validateSession(session);
    
    if (!validation.valid) {
      await storage.delete(sessionId);
      throw new SessionExpiredError(`Session ${validation.reason}`);
    }
    
    // Refresh if needed
    if (validation.shouldRefresh) {
      await refreshSession(session, storage);
    }
    
    res.json({ userId: session.userId });
  } catch (error) {
    next(error);
  }
});

// Admin-only route
app.get('/api/admin', async (req, res, next) => {
  try {
    const sessionId = req.headers.authorization?.split(' ')[1];
    
    if (!sessionId) {
      throw new UnauthenticatedError('No session provided');
    }
    
    const session = await storage.get(sessionId);
    
    if (!session) {
      throw new UnauthenticatedError('Session not found');
    }
    
    // Check role
    const isAdmin = session.data?.roles?.includes('admin');
    
    if (!isAdmin) {
      throw new ForbiddenError('Admin access required');
    }
    
    res.json({ admin: true });
  } catch (error) {
    next(error);
  }
});

// Error handler middleware
app.use((err, req, res, next) => {
  // Log error
  console.error('Error:', err);
  
  // Handle auth errors
  if (isAuthError(err)) {
    // Add custom logging for specific errors
    if (isSessionError(err)) {
      console.log('Session error:', err.code);
    }
    
    if (isValidationError(err)) {
      console.log('Validation errors:', err.metadata?.errors);
    }
    
    return res.status(err.statusCode).json(err.toJSON());
  }
  
  // Handle other errors
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

app.listen(3000);
```

## Error Codes Reference

| Error Class | Code | Status | Description |
|------------|------|--------|-------------|
| `UnauthenticatedError` | `UNAUTHENTICATED` | 401 | User not authenticated |
| `InvalidCredentialsError` | `INVALID_CREDENTIALS` | 401 | Wrong username/password |
| `AccountLockedError` | `ACCOUNT_LOCKED` | 403 | Account is locked |
| `FingerprintMismatchError` | `FINGERPRINT_MISMATCH` | 401 | Session fingerprint mismatch |
| `SessionExpiredError` | `SESSION_EXPIRED` | 401 | Session has expired |
| `SessionNotFoundError` | `SESSION_NOT_FOUND` | 401 | Session not in storage |
| `SessionRevokedError` | `SESSION_REVOKED` | 401 | Session was revoked |
| `ConcurrentSessionError` | `CONCURRENT_SESSION` | 429 | Too many sessions |
| `InvalidSessionError` | `INVALID_SESSION` | 400 | Session data invalid |
| `InvalidCookieError` | `INVALID_COOKIE` | 400 | Cookie format invalid |
| `CookieSignatureMismatchError` | `COOKIE_SIGNATURE_MISMATCH` | 401 | Cookie signature invalid |
| `CookieDecryptionError` | `COOKIE_DECRYPTION_ERROR` | 400 | Decryption failed |
| `InvalidTokenError` | `INVALID_TOKEN` | 401 | Token format invalid |
| `TokenExpiredError` | `TOKEN_EXPIRED` | 401 | Token has expired |
| `TokenRevokedError` | `TOKEN_REVOKED` | 401 | Token was revoked |
| `ValidationError` | `VALIDATION_ERROR` | 400 | Input validation failed |
| `UnauthorizedError` | `UNAUTHORIZED` | 403 | Not authorized |
| `ForbiddenError` | `FORBIDDEN` | 403 | Access forbidden |
| `InsufficientPermissionsError` | `INSUFFICIENT_PERMISSIONS` | 403 | Missing permissions |

## Best Practices

1. **Use Specific Errors**: Don't just throw generic `Error`, use specific error classes
2. **Include Context**: Add metadata to help debug issues
3. **Log Appropriately**: Log errors but sanitize sensitive data
4. **Use Type Guards**: Check error types before handling
5. **Don't Expose Internals**: Sanitize error messages for production
6. **Handle All Cases**: Use comprehensive error handling in middleware
7. **Map to HTTP Status**: Use built-in status codes for consistent API responses
8. **Provide User-Friendly Messages**: Generic messages for security, detailed for development
9. **Track Error Patterns**: Monitor error types and frequencies
10. **Test Error Paths**: Write tests for error scenarios

## Error Logging Example

```typescript
import { AuthError, isAuthError } from '@amtarc/auth-utils/errors';

function logError(error: unknown, context?: Record<string, unknown>) {
  if (isAuthError(error)) {
    // Structured logging
    console.error({
      type: 'auth_error',
      code: error.code,
      message: error.message,
      statusCode: error.statusCode,
      timestamp: error.timestamp,
      metadata: error.metadata,
      context
    });
    
    // Send to monitoring service
    if (process.env.NODE_ENV === 'production') {
      monitoringService.logError({
        error: error.toJSON(),
        context
      });
    }
  } else {
    console.error('Unknown error:', error);
  }
}

// Usage
try {
  // ... your code
} catch (error) {
  logError(error, {
    userId: req.user?.id,
    endpoint: req.url,
    method: req.method
  });
  
  throw error; // Re-throw for middleware
}
```

## Next Steps

- [Session Management](/guide/sessions) - Session lifecycle and errors
- [Guards](/guide/guards) - Error handling in guards
- [Cookies](/guide/cookies) - Cookie error handling
- [API Reference](/api/core) - Complete API documentation
