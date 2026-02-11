# @amtarc-auth-utils/core

> Core authentication and session management utilities

## Installation

```bash
pnpm add @amtarc-auth-utils/core
```

## Features

- ✅ Session creation and validation
- ✅ Session guards and middleware
- ✅ Framework-agnostic design
- ✅ TypeScript-first with full type safety
- ✅ Zero runtime dependencies

## Quick Start

```typescript
import { createSession, validateSession, requireSession } from '@amtarc-auth-utils/core';

// Create a session
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24, // 24 hours
  idleTimeout: 1000 * 60 * 30, // 30 minutes
});

// Validate a session
const validation = validateSession(session);
if (!validation.valid) {
  console.error('Session invalid:', validation.reason);
}

// Use as a guard
const getSession = () => getCurrentSession(); // Your session retrieval logic
const guard = requireSession(getSession);

const handler = guard(async (session) => {
  return { userId: session.userId };
});
```

## API Reference

### `createSession(userId, options)`

Creates a new session for a user.

**Parameters:**
- `userId` (string): The user ID
- `options` (SessionOptions): Configuration options
  - `expiresIn` (number): Session lifetime in milliseconds (default: 7 days)
  - `idleTimeout` (number): Idle timeout in milliseconds
  - `fingerprint` (boolean): Enable session fingerprinting

**Returns:** `Session<TUser>`

### `validateSession(session, options)`

Validates a session against expiration and idle timeout rules.

**Parameters:**
- `session` (Session): The session to validate
- `options` (SessionOptions): Validation options

**Returns:** `ValidationResult`

### `requireSession(getSession, options)`

Creates a guard that requires a valid session.

**Parameters:**
- `getSession` (() => Session | Promise<Session | null>): Function to retrieve session
- `options` (SessionOptions): Session validation options

**Returns:** Guard function

## License

MIT
