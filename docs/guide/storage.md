# Storage & Integration

Complete guide to unified storage adapters, cross-module integration, and storage patterns for sessions, CSRF, and rate limiting.

## Overview

The storage module provides:

- Unified storage interfaces for all modules
- Universal memory storage adapter that works everywhere
- Session-CSRF integration for storing tokens in sessions
- Type-safe storage operations with TypeScript
- Counter operations for rate limiting
- Cross-module storage sharing and integration

## Storage Interfaces

### BaseStorage

Foundation interface for all storage operations.

```typescript
import { BaseStorage } from '@amtarc/auth-utils/storage';

interface BaseStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}
```

**Methods:**
- `get()` - Retrieve value by key (null if expired/missing)
- `set()` - Store value with optional TTL in milliseconds
- `delete()` - Remove value
- `exists()` - Check if key exists and is not expired

### CounterStorage

Extends BaseStorage with atomic counter operations for rate limiting.

```typescript
import { CounterStorage } from '@amtarc/auth-utils/storage';

interface CounterStorage extends BaseStorage {
  increment(key: string, amount?: number): Promise<number>;
  decrement(key: string, amount?: number): Promise<number>;
}
```

**Methods:**
- `increment()` - Atomically increment counter (default: +1)
- `decrement()` - Atomically decrement counter (default: -1)

## UniversalMemoryStorage

In-memory storage adapter that works with all modules.

### Basic Usage

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';

// Create storage instance
const storage = new UniversalMemoryStorage({
  cleanupIntervalMs: 60000 // Clean expired entries every 60s
});

// Store with TTL
await storage.set('session:123', sessionData, 3600000); // 1 hour

// Retrieve
const data = await storage.get('session:123');

// Check existence
const exists = await storage.exists('session:123');

// Delete
await storage.delete('session:123');

// Counter operations
await storage.increment('rate:user-123'); // Returns 1
await storage.increment('rate:user-123', 5); // Returns 6
await storage.decrement('rate:user-123'); // Returns 5
```

### Constructor Options

```typescript
interface UniversalMemoryStorageOptions {
  /** Cleanup interval in milliseconds (default: 60000) */
  cleanupIntervalMs?: number;
}
```

### With Sessions

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import { createSession } from '@amtarc/auth-utils/session';
import type { StorageOptions } from '@amtarc/auth-utils/session';

const storage = new UniversalMemoryStorage();

// Create session
const session = createSession('user-123', {
  expiresIn: 3600000 // 1 hour
});

// Store with StorageOptions object
await storage.set(session.id, session, {
  ttl: 3600, // TTL in seconds
  metadata: {
    device: 'mobile',
    platform: 'iOS'
  }
});

// Retrieve session
const retrieved = await storage.get(session.id);
```

### With CSRF Protection

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import { generateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
import type { CSRFStorageAdapter } from '@amtarc/auth-utils/security/csrf';

const storage = new UniversalMemoryStorage();

// Use with CSRF (direct storage)
const { token } = await generateSynchronizerToken({
  session,
  storage: storage as unknown as CSRFStorageAdapter,
  lifetime: 3600000 // 1 hour in ms
});

// CSRF tokens stored with TTL
await storage.set('csrf:session-123', 'token-xyz', 3600000);
```

### With Rate Limiting

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import { createRateLimiter } from '@amtarc/auth-utils/security/rate-limit';

const storage = new UniversalMemoryStorage();

// Create rate limiter using the storage
const limiter = createRateLimiter({
  storage,
  max: 100, // 100 requests
  window: 60000 // per minute
});

// Check rate limit
const result = await limiter('user-123');
if (!result.allowed) {
  throw new Error(`Rate limit exceeded. Retry in ${result.retryAfter}ms`);
}
```

### Utility Methods

```typescript
// Get storage size
const count = storage.size();
console.log(`${count} items in storage`);

// Clear all data
storage.clear();

// Cleanup expired entries
const cleaned = await storage.cleanup();
console.log(`Cleaned ${cleaned} expired entries`);

// Stop cleanup interval and clear data
storage.destroy();
```

## Cross-Module Integration

### Single Storage for All Modules

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import { createSession } from '@amtarc/auth-utils/session';
import { generateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
import { createRateLimiter } from '@amtarc/auth-utils/security/rate-limit';
import type { CSRFStorageAdapter } from '@amtarc/auth-utils/security/csrf';

// One storage instance for everything
const storage = new UniversalMemoryStorage();

// 1. Store session
const session = createSession('user-123', {
  expiresIn: 3600000
});
await storage.set(session.id, session, 3600000);

// 2. Generate CSRF token (uses same storage)
const { token } = await generateSynchronizerToken({
  session,
  storage: storage as unknown as CSRFStorageAdapter,
  lifetime: 3600000
});

// 3. Rate limit (uses same storage)
const limiter = createRateLimiter({
  storage,
  max: 100,
  window: 60000
});
await limiter(session.userId);

// All data in one place!
console.log(`Total items: ${storage.size()}`);
```

## SessionCSRFAdapter

Store CSRF tokens inside session data instead of separate storage.

### Basic Usage

```typescript
import { SessionCSRFAdapter } from '@amtarc/auth-utils/security/csrf';
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import { createSession } from '@amtarc/auth-utils/session';
import { generateSynchronizerToken, validateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
import type { SessionStorageAdapter } from '@amtarc/auth-utils/session';

const storage = new UniversalMemoryStorage();

// Create and store session
const session = createSession('user-123', {
  expiresIn: 3600000
});
await storage.set(session.id, session, 3600000);

// Create CSRF adapter that stores in session
const csrfAdapter = new SessionCSRFAdapter(
  storage as unknown as SessionStorageAdapter,
  session.id
);

// Generate CSRF token (stored in session.csrf field)
const { token } = await generateSynchronizerToken({
  session,
  storage: csrfAdapter
});

// Validate CSRF token
const result = await validateSynchronizerToken(token, {
  session,
  storage: csrfAdapter
});

console.log(result.valid); // true

// CSRF tokens are now part of session data
const sessionData = await storage.get(session.id);
console.log(sessionData.csrf); // { 'csrf:session-id': { token, expiresAt } }
```

### Benefits

1. **Simplified Architecture**: CSRF tokens tied to session lifecycle
2. **Automatic Cleanup**: Tokens deleted when session expires
3. **Fewer Storage Keys**: One session = one storage entry
4. **Transactional**: Session + CSRF updated together

### When to Use

**Use SessionCSRFAdapter when:**
- CSRF tokens should expire with sessions
- You want simplified storage architecture
- Session size is not a concern
- Single-page applications with long sessions

**Use Direct Storage when:**
- Different TTL for CSRF vs sessions
- Minimal session payload required
- Distributed systems with session replication
- Need independent CSRF token management

## Session-Specific Methods

UniversalMemoryStorage includes session-specific methods for multi-device support.

### User Session Tracking

```typescript
const storage = new UniversalMemoryStorage();

// Create sessions for a user
const session1 = createSession('user-123', { expiresIn: 3600000 });
const session2 = createSession('user-123', { expiresIn: 3600000 });

await storage.set(session1.id, session1, 3600000);
await storage.set(session2.id, session2, 3600000);

// Get all sessions for user
const userSessions = await storage.getUserSessions('user-123');
console.log(userSessions); // ['session1-id', 'session2-id']

// Delete all user sessions
await storage.deleteUserSessions('user-123');
```

### Session Touch (Update TTL)

```typescript
// Extend session TTL without modifying data
await storage.touch(session.id, 3600); // 3600 seconds (1 hour)
```

## Advanced Patterns

### Storage with Metadata

```typescript
const storage = new UniversalMemoryStorage();

// Store with metadata
await storage.set('session:123', sessionData, {
  ttl: 3600, // seconds
  metadata: {
    device: 'iPhone 14 Pro',
    os: 'iOS 17',
    browser: 'Safari',
    lastIp: '192.168.1.1'
  }
});

// Metadata is preserved but not exposed via get()
// Useful for logging and debugging
```

### Cleanup and Monitoring

```typescript
const storage = new UniversalMemoryStorage({
  cleanupIntervalMs: 30000 // Cleanup every 30s
});

// Manual cleanup
setInterval(async () => {
  const cleaned = await storage.cleanup();
  if (cleaned > 0) {
    console.log(`Cleaned ${cleaned} expired entries`);
  }
}, 60000);

// Monitor size
setInterval(() => {
  const size = storage.size();
  console.log(`Storage size: ${size} entries`);
  
  if (size > 10000) {
    console.warn('Storage size exceeding threshold!');
  }
}, 300000); // Every 5 minutes
```

### Multi-Tenant Storage

```typescript
// Namespace keys for multi-tenant applications
class TenantStorage {
  constructor(
    private storage: UniversalMemoryStorage,
    private tenantId: string
  ) {}

  private makeKey(key: string): string {
    return `tenant:${this.tenantId}:${key}`;
  }

  async set(key: string, value: unknown, ttl?: number) {
    return this.storage.set(this.makeKey(key), value, ttl);
  }

  async get(key: string) {
    return this.storage.get(this.makeKey(key));
  }

  async delete(key: string) {
    return this.storage.delete(this.makeKey(key));
  }
}

// Usage
const storage = new UniversalMemoryStorage();
const tenant1 = new TenantStorage(storage, 'acme-corp');
const tenant2 = new TenantStorage(storage, 'widgets-inc');

await tenant1.set('session:123', data1);
await tenant2.set('session:123', data2); // Different data!
```

## Type Safety

### Storage with TypeScript

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import type { Session } from '@amtarc/auth-utils';

const storage = new UniversalMemoryStorage();

// Type assertion for type safety
async function getSession(sessionId: string): Promise<Session | null> {
  const data = await storage.get(sessionId);
  return data as Session | null;
}

// Store typed data
interface UserPreferences {
  theme: 'light' | 'dark';
  language: string;
}

await storage.set('prefs:user-123', {
  theme: 'dark',
  language: 'en'
} as UserPreferences);

const prefs = await storage.get('prefs:user-123') as UserPreferences | null;
```

## Performance Considerations

### Memory Usage

```typescript
// UniversalMemoryStorage keeps everything in RAM
// Monitor memory usage in production

const storage = new UniversalMemoryStorage();

// Estimate memory usage
const entries = storage.size();
const avgEntrySize = 1024; // bytes (adjust based on your data)
const estimatedMemory = entries * avgEntrySize;

console.log(`Estimated memory: ${estimatedMemory / 1024 / 1024} MB`);
```

### Cleanup Strategy

```typescript
// Aggressive cleanup for high-traffic applications
const storage = new UniversalMemoryStorage({
  cleanupIntervalMs: 10000 // Every 10 seconds
});

// Or manual cleanup on specific events
app.on('request-ended', async () => {
  await storage.cleanup();
});
```

### Production Recommendations

```typescript
// For production, consider:

// 1. Redis adapter for persistence and distributed systems
class RedisStorage implements CounterStorage {
  // Implementation using ioredis or node-redis
}

// 2. Memory limits with LRU eviction
class LRUMemoryStorage extends UniversalMemoryStorage {
  constructor(private maxEntries: number) {
    super();
  }
  // Override set() to enforce limit
}

// 3. Hybrid approach: Memory + Redis fallback
class HybridStorage implements CounterStorage {
  constructor(
    private memory: UniversalMemoryStorage,
    private redis: RedisStorage
  ) {}
  
  async get(key: string) {
    // Try memory first, fallback to Redis
    const cached = await this.memory.get(key);
    if (cached !== null) return cached;
    
    const value = await this.redis.get(key);
    if (value !== null) {
      await this.memory.set(key, value);
    }
    return value;
  }
}
```

## Migration Guide

### From Separate Storage to Universal

Before:
```typescript
const sessionStorage = new MemoryStorageAdapter();
const csrfStorage = new MemoryCSRFStorage();
const rateLimitStorage = new MemoryRateLimitStorage();
```

After:
```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';

// One storage for all!
const storage = new UniversalMemoryStorage();

// Use with type assertions where needed
const sessionStorage = storage;
const csrfStorage = storage as unknown as CSRFStorageAdapter;
const rateLimitStorage = storage;
```

## Best Practices

1. **Single Instance**: Use one UniversalMemoryStorage instance per application
2. **Namespace Keys**: Use prefixes to avoid key collisions (`session:`, `csrf:`, `rate:`)
3. **Monitor Size**: Track storage size and set up alerts
4. **Cleanup Interval**: Adjust based on traffic (10s for high-traffic, 60s for low-traffic)
5. **TTL Strategy**: Always set TTL to prevent memory leaks
6. **Graceful Shutdown**: Call `destroy()` on application shutdown
7. **Testing**: Mock storage in tests, use real instance in integration tests
8. **Production**: Consider Redis/database adapters for persistence

## Examples

### Complete Integration Example

```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
import { createSession, validateSession } from '@amtarc/auth-utils/session';
import { SessionCSRFAdapter, generateSynchronizerToken, validateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
import { createRateLimiter } from '@amtarc/auth-utils/security/rate-limit';
import type { SessionStorageAdapter } from '@amtarc/auth-utils/session';

// Setup
const storage = new UniversalMemoryStorage({ cleanupIntervalMs: 30000 });

// 1. User logs in - create session
async function login(userId: string) {
  const session = createSession(userId, {
    expiresIn: 3600000 // 1 hour
  });
  
  await storage.set(session.id, session, 3600000);
  
  return session;
}

// 2. Protect request with CSRF
async function handleProtectedRequest(sessionId: string, csrfToken: string) {
  // Get session
  const session = await storage.get(sessionId);
  if (!session) throw new Error('Session not found');
  
  // Validate session
  const validation = validateSession(session);
  if (!validation.valid) throw new Error('Session expired');
  
  // Validate CSRF
  const csrfAdapter = new SessionCSRFAdapter(
    storage as unknown as SessionStorageAdapter,
    sessionId
  );
  
  const csrfResult = await validateSynchronizerToken(csrfToken, {
    session,
    storage: csrfAdapter
  });
  
  if (!csrfResult.valid) throw new Error('Invalid CSRF token');
  
  // Check rate limit
  const limiter = createRateLimiter({
    storage,
    max: 100,
    window: 60000
  });
  
  const rateLimit = await limiter(session.userId);
  if (!rateLimit.allowed) {
    throw new Error(`Rate limit exceeded. Retry in ${rateLimit.retryAfter}ms`);
  }
  
  // Process request...
  return { success: true };
}

// 3. Logout - cleanup
async function logout(userId: string) {
  await storage.deleteUserSessions(userId);
}

// 4. Periodic maintenance
setInterval(async () => {
  const cleaned = await storage.cleanup();
  console.log(`Maintenance: cleaned ${cleaned} entries, ${storage.size()} remaining`);
}, 60000);
```

## Related Documentation

- [Session Management](./sessions.md) - Session lifecycle and management
- [Security Features](./security.md) - CSRF, rate limiting, and encryption
- [API Reference](/api/core.md#storage) - Complete storage API
