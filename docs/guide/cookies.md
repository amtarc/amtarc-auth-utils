# Secure Cookie Management

Complete guide to creating, parsing, signing, encrypting, and managing secure cookies with RFC 6265 compliance.

## Overview

The cookie module provides:

- RFC 6265 compliant cookie creation and parsing
- HMAC-SHA256 signature signing and verification
- AES-256-GCM encryption and decryption
- Cookie rotation with single-use guarantees
- Secure deletion with past expiration
- Validation for names, values, domains, paths
- Attribute support (HttpOnly, Secure, SameSite, etc.)

## Creating Cookies

### Basic Cookie Creation

```typescript
import { createAuthCookie } from '@amtarc/auth-utils/cookies';

const cookie = createAuthCookie('session', 'session_123', {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 60 * 60 * 24, // 1 day in seconds
  path: '/',
  domain: 'example.com'
});

console.log(cookie);
// "session=session_123; HttpOnly; Secure; SameSite=Strict; Max-Age=86400; Path=/; Domain=example.com"

// Set in response
res.setHeader('Set-Cookie', cookie);
```

### Cookie Options

```typescript
interface CookieOptions {
  /** Max age in seconds */
  maxAge?: number;
  
  /** Expiration date  */
  expires?: Date;
  
  /** Cookie path */
  path?: string;
  
  /** Cookie domain */
  domain?: string;
  
  /** Secure flag (HTTPS only) */
  secure?: boolean;
  
  /** HttpOnly flag (no JavaScript access) */
  httpOnly?: boolean;
  
  /** SameSite policy */
  sameSite?: 'strict' | 'lax' | 'none';
  
  /** Partitioned attribute (CHIPS) */
  partitioned?: boolean;
}
```

### Recommended Security Settings

```typescript
// Production cookie settings
const secureCookie = createAuthCookie('session', sessionId, {
  httpOnly: true,        // Prevent JavaScript access
  secure: true,          // HTTPS only
  sameSite: 'strict',    // Prevent CSRF
  maxAge: 60 * 60 * 24,  // 1 day
  path: '/',             // Site-wide
  // domain: '.example.com' // Uncomment for subdomain access
});
```

## Parsing Cookies

### Parse Single Cookie

```typescript
import { getAuthCookie } from '@amtarc/auth-utils/cookies';

const cookieHeader = 'session=abc123; userId=456; theme=dark';

const sessionCookie = getAuthCookie(cookieHeader, 'session');

console.log(sessionCookie);
// {
//   name: 'session',
//   value: 'abc123',
//   httpOnly: false,
//   secure: false,
//   sameSite: undefined,
//   // ... other properties
// }
```

### Parse All Cookies

```typescript
import { parseAuthCookies } from '@amtarc/auth-utils/cookies';

const cookieHeader = 'session=abc123; userId=456; theme=dark';

const allCookies = parseAuthCookies(cookieHeader);

console.log(allCookies);
// {
//   session: 'abc123',
//   userId: '456',
//   theme: 'dark'
// }
```

### Get Cookie Value

```typescript
import { getCookieValue } from '@amtarc/auth-utils/cookies';

const sessionId = getCookieValue(req.headers.cookie, 'session');

if (sessionId) {
  // Use session ID
}
```

## Signed Cookies

Signed cookies prevent tampering using HMAC-SHA256.

### Sign a Cookie

```typescript
import { createAuthCookie, signCookie } from '@amtarc/auth-utils/cookies';

const SECRET = 'your-secret-key-min-32-chars';

const cookie = createAuthCookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});

const signed = signCookie(cookie, SECRET);
// "session=session_123.signature; HttpOnly; Secure; SameSite=Strict"

res.setHeader('Set-Cookie', signed);
```

### Verify Signed Cookie

```typescript
import { unsignCookie } from '@amtarc/auth-utils/cookies';

const result = unsignCookie(req.headers.cookie, 'session', SECRET);

if (result.valid) {
  console.log('Session ID:', result.value);
} else {
  console.error('Cookie signature invalid or missing');
}
```

### Verify with Strict Validation

```typescript
const result = unsignCookie(req.headers.cookie, 'session', SECRET, {
  strict: true // Throw error if invalid
});

// If we reach here, cookie is valid
const sessionId = result.value;
```

## Encrypted Cookies

Encrypted cookies protect sensitive data using AES-256-GCM.

### Encrypt a Cookie

```typescript
import { createAuthCookie, encryptCookie } from '@amtarc/auth-utils/cookies';

const SECRET = 'your-secret-key-min-32-chars';

const cookie = createAuthCookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
});

const encrypted = await encryptCookie(cookie, SECRET);
// Cookie value is encrypted with iv:authTag:ciphertext format

res.setHeader('Set-Cookie', encrypted);
```

### Decrypt a Cookie

```typescript
import { decryptCookie } from '@amtarc/auth-utils/cookies';

const result = await decryptCookie(req.headers.cookie, 'session', SECRET);

if (result.valid) {
  console.log('Session ID:', result.value);
} else {
  console.error('Failed to decrypt cookie');
}
```

### Decrypt with Strict Validation

```typescript
const result = await decryptCookie(req.headers.cookie, 'session', SECRET, {
  strict: true // Throw error if decryption fails
});

// If we reach here, decryption succeeded
const sessionId = result.value;
```

## Cookie Rotation

Rotate cookie values while maintaining single-use guarantees:

```typescript
import { rotateCookie } from '@amtarc/auth-utils/cookies';

// Original cookie
const oldCookie = createAuthCookie('session', 'old_session_id', {
  httpOnly: true,
  secure: true
});

// Rotate to new value
const newCookie = rotateCookie(oldCookie, 'new_session_id');

// Old cookie is set to expire immediately
// New cookie has same options as old cookie
res.setHeader('Set-Cookie', [oldCookie, newCookie]);
```

## Cookie Deletion

### Delete a Cookie

```typescript
import { deleteAuthCookie } from '@amtarc/auth-utils/cookies';

// Create deletion cookie (expires in the past)
const deleted = deleteAuthCookie('session', {
  path: '/',
  domain: 'example.com' // Must match original cookie
});

res.setHeader('Set-Cookie', deleted);
```

### Delete All Cookies

```typescript
import { deleteAuthCookies } from '@amtarc/auth-utils/cookies';

const cookieNames = ['session', 'refresh_token', 'csrf'];

const deletedCookies = deleteAuthCookies(cookieNames, {
  path: '/',
  domain: 'example.com'
});

res.setHeader('Set-Cookie', deletedCookies);
```

## Validation

The library validates cookies according to RFC 6265:

### Cookie Name Validation

```typescript
// Valid names: alphanumeric, -, _, !#$%&'*+.^`|~
createAuthCookie('my-session_123', 'value'); // Valid
createAuthCookie('my cookie', 'value'); // Throws: Invalid cookie name
createAuthCookie('my=cookie', 'value'); // Throws: Invalid cookie name
```

### Cookie Value Validation

```typescript
// Values are automatically encoded
createAuthCookie('data', 'hello world'); // Value is encoded
createCookie('data', 'value,with,commas'); // Encoded

// Control characters are rejected
createCookie('data', 'value\nwith\nnewlines'); // Throws: Invalid cookie value
```

### Domain Validation

```typescript
// Valid domains
createCookie('session', 'value', { domain: 'example.com' }); // Valid
createCookie('session', 'value', { domain: '.example.com' }); // Valid subdomain

// Invalid domains
createCookie('session', 'value', { domain: 'not a domain' }); // Throws
```

### Path Validation

```typescript
// Valid paths
createCookie('session', 'value', { path: '/' }); // Valid
createCookie('session', 'value', { path: '/api' }); // Valid

// Invalid paths
createCookie('session', 'value', { path: 'no-slash' }); // Throws
```

## Complete Examples

### Express Session Management

```typescript
import express from 'express';
import cookieParser from 'cookie-parser';
import {
  createCookie,
  signCookie,
  verifyCookie,
  deleteCookie
} from '@amtarc/auth-utils/cookies';
import { createSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const app = express();
app.use(cookieParser());

const storage = new MemoryStorageAdapter();
const COOKIE_SECRET = process.env.COOKIE_SECRET;

// Login
app.post('/login', async (req, res) => {
  // Authenticate user...
  const userId = 'user-123';
  
  // Create session
  const session = createSession(userId, {
    expiresIn: 1000 * 60 * 60 * 24
  });
  
  await storage.set(session.sessionId, session);
  
  // Create signed cookie
  const cookie = createCookie('session', session.sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24
  });
  
  const signed = signCookie(cookie, COOKIE_SECRET);
  
  res.setHeader('Set-Cookie', signed);
  res.json({ success: true });
});

// Authenticated endpoint
app.get('/api/profile', async (req, res) => {
  const result = verifyCookie(req.headers.cookie, 'session', COOKIE_SECRET);
  
  if (!result.valid) {
    return res.status(401).json({ error: 'Invalid session cookie' });
  }
  
  const session = await storage.get(result.value);
  
  if (!session) {
    return res.status(401).json({ error: 'Session not found' });
  }
  
  res.json({ userId: session.userId });
});

// Logout
app.post('/logout', async (req, res) => {
  const result = verifyCookie(req.headers.cookie, 'session', COOKIE_SECRET);
  
  if (result.valid) {
    await storage.delete(result.value);
  }
  
  const deleted = deleteCookie('session', {
    path: '/',
    domain: req.hostname
  });
  
  res.setHeader('Set-Cookie', deleted);
  res.json({ success: true });
});

app.listen(3000);
```

### Next.js with Encrypted Cookies

```typescript
// app/actions/auth.ts
'use server';

import { cookies } from 'next/headers';
import { createCookie, encryptCookie, decryptCookie } from '@amtarc/auth-utils/cookies';
import { createSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();
const ENCRYPTION_KEY = process.env.COOKIE_ENCRYPTION_KEY;

export async function login(userId: string) {
  const session = createSession(userId, {
    expiresIn: 1000 * 60 * 60 * 24
  });
  
  await storage.set(session.sessionId, session);
  
  const cookie = createCookie('session', session.sessionId, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24
  });
  
  const encrypted = await encryptCookie(cookie, ENCRYPTION_KEY);
  
  // Parse encrypted cookie to set in Next.js
  const [nameValue, ...attrs] = encrypted.split('; ');
  const [name, value] = nameValue.split('=');
  
  cookies().set(name, value, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24
  });
  
  return { success: true };
}

export async function getSession() {
  const cookieHeader = cookies().toString();
  const result = await decryptCookie(cookieHeader, 'session', ENCRYPTION_KEY);
  
  if (!result.valid) {
    return null;
  }
  
  return await storage.get(result.value);
}

export async function logout() {
  const cookieHeader = cookies().toString();
  const result = await decryptCookie(cookieHeader, 'session', ENCRYPTION_KEY);
  
  if (result.valid) {
    await storage.delete(result.value);
  }
  
  cookies().delete('session');
  
  return { success: true };
}
```

### Fastify with Cookie Rotation

```typescript
import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import {
  createCookie,
  signCookie,
  rotateCookie,
  verifyCookie
} from '@amtarc/auth-utils/cookies';
import { createSession, refreshSession } from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const fastify = Fastify();
fastify.register(fastifyCookie);

const storage = new MemoryStorageAdapter();
const SECRET = process.env.COOKIE_SECRET;

// Refresh session with cookie rotation
fastify.post('/refresh', async (request, reply) => {
  const cookieResult = verifyCookie(request.headers.cookie, 'session', SECRET);
  
  if (!cookieResult.valid) {
    return reply.code(401).send({ error: 'Invalid session' });
  }
  
  const oldSession = await storage.get(cookieResult.value);
  
  if (!oldSession) {
    return reply.code(401).send({ error: 'Session not found' });
  }
  
  // Refresh session (rotates session ID)
  const newSession = await refreshSession(oldSession, storage, {
    rotateId: true
  });
  
  // Rotate cookie
  const oldCookie = createCookie('session', oldSession.sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  });
  
  const newCookie = rotateCookie(oldCookie, newSession.sessionId);
  const signed = signCookie(newCookie, SECRET);
  
  reply.header('Set-Cookie', signed);
  reply.send({ success: true });
});

fastify.listen({ port: 3000 });
```

## Best Practices

1. **Always Use HttpOnly**: Prevent JavaScript access to cookies
2. **Use Secure in Production**: Ensure cookies are only sent over HTTPS
3. **Set SameSite**: Prevent CSRF attacks with 'strict' or 'lax'
4. **Sign or Encrypt Session Cookies**: Prevent tampering
5. **Rotate on Privilege Changes**: Change session ID on login/role changes
6. **Set Appropriate MaxAge**: Balance security and user experience
7. **Match Domain/Path on Delete**: Must match original cookie settings
8. **Use Strong Secrets**: Minimum 32 characters, cryptographically random
9. **Don't Store Sensitive Data**: Even encrypted cookies can be stolen
10. **Validate All Inputs**: Library validates names/values/domains/paths

## Security Considerations

### HMAC Signing vs Encryption

- **Signing**: Prevents tampering but data is readable
- **Encryption**: Hides data and prevents tampering

Use signing for non-sensitive IDs, encryption for sensitive data.

### Cookie Size Limits

Browsers limit cookies to ~4KB. Keep values small:

- Use session IDs instead of full session data in cookies
- Store data server-side, use cookie as reference
- Compress data if necessary (not recommended)

### SameSite Attribute

- `strict`: Cookie only sent to same site (best security)
- `lax`: Cookie sent on top-level navigation (balance)
- `none`: Cookie sent to all sites (requires Secure, least secure)

### Subdomain Cookies

```typescript
// Cookie available to all subdomains
createCookie('session', sessionId, {
  domain: '.example.com' // Note the leading dot
});

// Cookie only for specific subdomain
createCookie('session', sessionId, {
  domain: 'app.example.com' // No leading dot
});
```

## Next Steps

- [Session Management](/guide/sessions) - Use cookies for session storage
- [Guards](/guide/guards) - Protect routes using cookies
- [Error Handling](/guide/errors) - Handle cookie errors
- [API Reference](/api/core) - Complete API documentation
