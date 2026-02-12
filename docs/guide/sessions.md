# Session Management

Complete guide to session management with multi-device support, fingerprinting, and storage adapters.

## Overview

The session management module provides:

- Session lifecycle management (create, validate, refresh, invalidate)
- Multi-device session tracking with device limits
- Session fingerprinting for security
- Storage adapters (Memory included, custom supported)
- Automatic session rotation and cleanup
- Idle timeout and absolute timeout support

## Creating Sessions

### Basic Session Creation

```typescript
import { createSession } from '@amtarc/auth-utils';

const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  idleTimeout: 1000 * 60 * 30,    // 30 minutes
  absoluteTimeout: 1000 * 60 * 60 * 24 * 7, // 7 days max
});

console.log(session);
// {
//   sessionId: 'sess_abc123...',
//   userId: 'user-123',
//   createdAt: 1234567890,
//   expiresAt: 1234654290,
//   lastActivityAt: 1234567890,
//   data: undefined,
//   fingerprint: undefined
// }
```

### Session with Custom Data

```typescript
interface UserData {
  email: string;
  roles: string[];
  preferences: {
    theme: 'light' | 'dark';
    language: string;
  };
}

const session = createSession<UserData>('user-123', {
  expiresIn: 1000 * 60 * 60 * 24,
  data: {
    email: 'user@example.com',
    roles: ['admin', 'editor'],
    preferences: {
      theme: 'dark',
      language: 'en'
    }
  }
});

// Fully typed access
const userEmail = session.data?.email; // string | undefined
const roles = session.data?.roles; // string[] | undefined
```

### Session with Fingerprinting

```typescript
import { createSession } from '@amtarc/auth-utils';
import { generateSessionFingerprint } from '@amtarc/auth-utils/session';

const fingerprint = generateSessionFingerprint({
  userAgent: req.headers['user-agent'],
  ip: req.ip,
  acceptLanguage: req.headers['accept-language']
});

const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24,
  fingerprint
});
```

## Session Validation

### Basic Validation

```typescript
import { validateSession } from '@amtarc/auth-utils';

const validation = validateSession(session);

if (!validation.valid) {
  console.error('Session invalid:', validation.reason);
  // reason: 'expired' | 'idle-timeout' | 'absolute-timeout'
}

if (validation.shouldRefresh) {
  // Session is >50% through its lifetime
  // Good time to refresh it
}
```

### Validation with Options

```typescript
const validation = validateSession(session, {
  idleTimeout: 1000 * 60 * 30, // 30 minutes
  absoluteTimeout: 1000 * 60 * 60 * 24 * 7, // 7 days
  refreshThreshold: 0.75 // Suggest refresh at 75% lifetime
});
```

### Fingerprint Validation

```typescript
import { validateFingerprint } from '@amtarc/auth-utils/session';

const currentFingerprint = generateSessionFingerprint({
  userAgent: req.headers['user-agent'],
  ip: req.ip,
  acceptLanguage: req.headers['accept-language']
});

const isValid = validateFingerprint(
  session,
  currentFingerprint,
  { strict: false } // Don't throw, just return false
);

if (!isValid) {
  // Possible session hijacking - handle accordingly
  await invalidateSession(storage, session.sessionId);
  throw new FingerprintMismatchError('Session fingerprint mismatch');
}
```

## Session Refresh

### Refresh with ID Rotation

```typescript
import { refreshSession } from '@amtarc/auth-utils/session';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter();

// Refresh and rotate session ID
const refreshed = await refreshSession(session, storage, {
  rotateId: true, // Generate new session ID
  expiresIn: 1000 * 60 * 60 * 24 // New expiration
});

console.log('New session ID:', refreshed.sessionId);
// Old session is automatically deleted from storage
```

### Refresh without Rotation

```typescript
const refreshed = await refreshSession(session, storage, {
  rotateId: false,
  expiresIn: 1000 * 60 * 60 * 24
});

// Session ID remains the same, only timestamps updated
```

## Session Invalidation

### Invalidate Single Session

```typescript
import { invalidateSession } from '@amtarc/auth-utils/session';

await invalidateSession(storage, session.sessionId);
// Session is removed from storage
```

### Invalidate All User Sessions

```typescript
import { invalidateAllSessions } from '@amtarc/auth-utils/session';

await invalidateAllSessions(storage, 'user-123');
// All sessions for user-123 are removed
```

## Storage Adapters

### Memory Storage

Built-in memory storage with automatic cleanup:

```typescript
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new MemoryStorageAdapter({
  cleanupInterval: 1000 * 60 * 5, // Cleanup every 5 minutes
  maxSize: 10000 // Max 10,000 sessions
});

// Store a session
await storage.set(session.sessionId, session);

// Retrieve a session
const retrieved = await storage.get(session.sessionId);

// Delete a session
await storage.delete(session.sessionId);

// Clean up expired sessions manually
await storage.cleanup();

// Destroy storage (stop cleanup, clear all data)
storage.destroy();
```

### Custom Storage Adapter

Implement your own storage (Redis, Database, etc.):

```typescript
import { SessionStorageAdapter, Session } from '@amtarc/auth-utils/session';

class RedisStorageAdapter<T = unknown> implements SessionStorageAdapter<T> {
  constructor(private redis: RedisClient) {}

  async get(sessionId: string): Promise<Session<T> | null> {
    const data = await this.redis.get(`session:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  async set(sessionId: string, session: Session<T>): Promise<void> {
    await this.redis.set(
      `session:${sessionId}`,
      JSON.stringify(session),
      'PX',
      session.expiresAt - Date.now()
    );
  }

  async delete(sessionId: string): Promise<void> {
    await this.redis.del(`session:${sessionId}`);
  }

  async cleanup(): Promise<void> {
    // Redis handles TTL automatically
  }
}
```

## Multi-Device Sessions

### Add Device Session

```typescript
import { addDeviceSession } from '@amtarc/auth-utils/session';

const device = await addDeviceSession(
  storage,
  'user-123',
  session.sessionId,
  {
    userAgent: req.headers['user-agent'],
    ip: req.ip,
    platform: 'web'
  },
  {
    maxDevices: 5, // Limit to 5 concurrent devices
    trustDevice: true
  }
);

console.log(device);
// {
//   deviceId: 'dev_abc123',
//   userId: 'user-123',
//   sessionId: 'sess_abc123',
//   fingerprint: '...',
//   trusted: true,
//   createdAt: 1234567890
// }
```

### Get Active Devices

```typescript
import { getActiveDevices } from '@amtarc/auth-utils/session';

const devices = await getActiveDevices(storage, 'user-123');

console.log(`User has ${devices.length} active devices`);
devices.forEach(device => {
  console.log(`- ${device.deviceId} (trusted: ${device.trusted})`);
});
```

### Revoke Device

```typescript
import { revokeDevice } from '@amtarc/auth-utils/session';

// Revoke specific device
await revokeDevice(storage, 'user-123', 'dev_abc123');

// Session for that device is invalidated
```

### Revoke All Devices Except Current

```typescript
import { revokeAllDevicesExcept } from '@amtarc/auth-utils/session';

await revokeAllDevicesExcept(storage, 'user-123', currentDeviceId);
// Useful for "logout all other devices" feature
```

## Session Fingerprinting

### Generate Fingerprint

```typescript
import { generateSessionFingerprint } from '@amtarc/auth-utils/session';

const fingerprint = generateSessionFingerprint({
  userAgent: req.headers['user-agent'],
  ip: req.ip,
  acceptLanguage: req.headers['accept-language'],
  platform: req.headers['sec-ch-ua-platform']
});

// Fingerprint is SHA-256 hash of normalized metadata
```

### Extract Metadata

```typescript
import { extractFingerprintMetadata } from '@amtarc/auth-utils/session';

const metadata = extractFingerprintMetadata(req, {
  // Optional overrides
  ip: req.headers['x-forwarded-for'] || req.ip
});

const fingerprint = generateSessionFingerprint(metadata);
```

### Validate Fingerprint

```typescript
import { validateFingerprint } from '@amtarc/auth-utils/session';

// Strict mode - throws on mismatch
try {
  validateFingerprint(session, metadata, { strict: true });
} catch (error) {
  if (error instanceof FingerprintMismatchError) {
    // Handle potential session hijacking
    await invalidateSession(storage, session.sessionId);
    throw error;
  }
}

// Non-strict - returns boolean
const isValid = validateFingerprint(session, metadata);
if (!isValid) {
  // Handle mismatch
}
```

## Complete Example

```typescript
import {
  createSession,
  validateSession,
  refreshSession,
  invalidateSession
} from '@amtarc/auth-utils';
import { MemoryStorageAdapter } from '@amtarc/auth-utils/session';
import {
  generateSessionFingerprint,
  validateFingerprint,
  addDeviceSession
} from '@amtarc/auth-utils/session';

// Setup
const storage = new MemoryStorageAdapter({
  cleanupInterval: 1000 * 60 * 5
});

// Login - create session with fingerprint
async function login(userId: string, req: Request) {
  const fingerprint = generateSessionFingerprint({
    userAgent: req.headers['user-agent'],
    ip: req.ip
  });

  const session = createSession(userId, {
    expiresIn: 1000 * 60 * 60 * 24,
    idleTimeout: 1000 * 60 * 30,
    fingerprint
  });

  await storage.set(session.sessionId, session);

  // Track device
  await addDeviceSession(storage, userId, session.sessionId, {
    userAgent: req.headers['user-agent'],
    ip: req.ip
  }, { maxDevices: 5 });

  return session;
}

// Validate session on each request
async function validateRequest(sessionId: string, req: Request) {
  const session = await storage.get(sessionId);
  if (!session) {
    throw new UnauthenticatedError('Session not found');
  }

  // Validate expiration
  const validation = validateSession(session);
  if (!validation.valid) {
    await invalidateSession(storage, sessionId);
    throw new SessionExpiredError(validation.reason);
  }

  // Validate fingerprint
  const metadata = {
    userAgent: req.headers['user-agent'],
    ip: req.ip
  };
  const fingerprintValid = validateFingerprint(session, metadata);
  if (!fingerprintValid) {
    await invalidateSession(storage, sessionId);
    throw new FingerprintMismatchError('Session fingerprint mismatch');
  }

  // Refresh if needed
  if (validation.shouldRefresh) {
    return await refreshSession(session, storage, { rotateId: true });
  }

  return session;
}

// Logout
async function logout(sessionId: string, userId: string) {
  await invalidateSession(storage, sessionId);
  // Or logout all devices:
  // await invalidateAllSessions(storage, userId);
}
```

## Best Practices

1. **Always Use Storage**: Don't store sessions in-memory unless using MemoryStorageAdapter
2. **Enable Fingerprinting**: Adds security against session hijacking
3. **Set Idle Timeout**: Automatically expire inactive sessions
4. **Rotate Session IDs**: On privilege escalation or periodic refresh
5. **Limit Devices**: Prevent unlimited concurrent sessions per user
6. **Clean Up Regularly**: Use automatic cleanup or scheduled cleanup
7. **Validate on Every Request**: Don't trust session IDs without validation
8. **Use Secure Cookies**: Always `httpOnly`, `secure`, and `sameSite: 'strict'`

## Next Steps

- [Guards](/guide/guards) - Protect routes with session validation
- [Cookies](/guide/cookies) - Secure cookie handling for sessions
- [Error Handling](/guide/errors) - Handle session errors properly
- [API Reference](/api/core) - Complete API documentation
