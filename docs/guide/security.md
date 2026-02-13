# Security Features

Complete guide to CSRF protection, rate limiting, security headers, and encryption utilities.

## Overview

The security module provides production-ready security features:

- **CSRF Protection**: Synchronizer token and double-submit cookie patterns
- **Rate Limiting**: Multiple algorithms (fixed window, sliding window, token bucket)
- **Brute Force Protection**: Account lockout and IP-based blocking
- **Security Headers**: CSP, HSTS, X-Frame-Options, and more
- **Encryption**: AES-256-GCM encryption with key derivation
- **Random Generation**: Cryptographically secure tokens and UUIDs

## CSRF Protection

### Synchronizer Token Pattern

Stores CSRF tokens on the server (most secure).

```typescript
import { generateSynchronizerToken, validateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
import { MemoryCSRFStorage } from '@amtarc/auth-utils/security/csrf';

const storage = new MemoryCSRFStorage();

// Generate token
const { token, sessionUpdated } = await generateSynchronizerToken({
  session,
  storage,
  regenerate: 'per-session', // or 'per-request', 'never'
  lifetime: 3600000 // 1 hour in ms
});

// Include in HTML form
const form = `
  <form method="POST" action="/update-profile">
    <input type="hidden" name="csrf_token" value="${token}" />
    <button type="submit">Update</button>
  </form>
`;

// Validate on submission
const result = await validateSynchronizerToken(submittedToken, {
  session,
  storage,
  deleteAfterUse: true, // Single-use token
  strict: false // Don't throw on failure
});

if (!result.valid) {
  throw new Error(`CSRF validation failed: ${result.reason}`);
}
```

### Double-Submit Cookie Pattern

Stores token in cookie (stateless).

```typescript
import { generateDoubleSubmitToken, validateDoubleSubmitToken } from '@amtarc/auth-utils/security/csrf';

// Generate token pair
const { token, hashedToken } = generateDoubleSubmitToken({
  session,
  lifetime: 3600000,
  includeSession: true
});

// Set cookie
res.setHeader('Set-Cookie', createAuthCookie('csrf', hashedToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict'
}));

// Include token in form
const form = `
  <input type="hidden" name="csrf_token" value="${token}" />
`;

// Validate submission
const result = await validateDoubleSubmitToken(submittedToken, {
  session,
  cookieToken: req.cookies.csrf,
  strict: false
});
```

### CSRF Token Generation Options

```typescript
interface CSRFTokenOptions {
  /** Token length in bytes (default: 32) */
  length?: number;
  
  /** Include timestamp in token (default: false) */
  includeTimestamp?: boolean;
  
  /** Token lifetime in ms (default: 3600000 = 1 hour) */
  lifetime?: number;
  
  /** Character set: 'base64' | 'hex' | 'alphanumeric' (default: 'base64') */
  charset?: string;
}
```

### CSRF Middleware Helper

```typescript
import { generateCSRFToken, attachCSRFTokenToHTML } from '@amtarc/auth-utils/security/csrf';

// Generate token
const token = generateCSRFToken({
  length: 32,
  includeTimestamp: true
});

// Auto-inject into HTML forms
const html = `
  <html>
    <body>
      <form method="POST">
        <button type="submit">Submit</button>
      </form>
    </body>
  </html>
`;

const injectedHTML = attachCSRFTokenToHTML(html, token, {
  formAttribute: 'data-csrf-form',
  inputName: '_csrf'
});
// All forms now have hidden CSRF input
```

### SessionCSRFStorage

Store CSRF tokens in session data:

```typescript
import { SessionCSRFStorage } from '@amtarc/auth-utils/security/csrf';

// Create storage that uses session.csrf property
const csrfStorage = new SessionCSRFStorage(() => session);

await csrfStorage.set('csrf:key', 'token-value', 3600000);
const token = await csrfStorage.get('csrf:key');

// CSRF tokens stored in session.csrf
console.log(session.csrf); // { 'csrf:key': { token, expiresAt } }
```

## Rate Limiting

### Basic Rate Limiter

```typescript
import { createRateLimiter } from '@amtarc/auth-utils/security/rate-limit';
import { MemoryRateLimitStorage } from '@amtarc/auth-utils/security/rate-limit';

const limiter = createRateLimiter({
  storage: new MemoryRateLimitStorage(),
  max: 100, // 100 requests
  window: 60000, // per minute
  algorithm: 'sliding-window-counter' // or 'fixed-window', 'sliding-window-log', 'token-bucket'
});

// Check rate limit
const result = await limiter('user-123');

if (!result.allowed) {
  throw new Error(`Rate limit exceeded. Try again in ${result.retryAfter}ms`);
}

console.log(`${result.remaining}/${result.limit} requests remaining`);
```

### Rate Limit Algorithms

#### 1. Fixed Window

```typescript
import { fixedWindow } from '@amtarc/auth-utils/security/rate-limit';

const check = fixedWindow({
  storage,
  max: 100,
  window: 60000
});

const result = await check('user-123');
// Window resets at fixed intervals
```

#### 2. Sliding Window Counter

```typescript
import { slidingWindowCounter } from '@amtarc/auth-utils/security/rate-limit';

const check = slidingWindowCounter({
  storage,
  max: 100,
  window: 60000
});

const result = await check('user-123');
// Smooths out fixed window burst problem
```

####3. Sliding Window Log

```typescript
import { slidingWindowLog } from '@amtarc/auth-utils/security/rate-limit';

const check = slidingWindowLog({
  storage,
  max: 100,
  window: 60000
});

const result = await check('user-123');
// Most accurate, stores all timestamps
```

#### 4. Token Bucket

```typescript
import { tokenBucket } from '@amtarc/auth-utils/security/rate-limit';

const check = tokenBucket({
  storage,
  capacity: 100, // Bucket size
  refillRate: 10, // Tokens per second
  window: 1000 // Check interval
});

const result = await check('user-123');
// Allows bursts up to capacity
```

### Multiple Rate Limiters

```typescript
// Per-user limit
const userLimiter = createRateLimiter({
  storage,
  max: 1000,
  window: 3600000 // 1000 requests per hour
});

// Per-IP limit (stricter)
const ipLimiter = createRateLimiter({
  storage,
  max: 100,
  window: 60000 // 100 requests per minute
});

// Check both
const userLimit = await userLimiter(userId);
const ipLimit = await ipLimiter(ipAddress);

if (!userLimit.allowed || !ipLimit.allowed) {
  throw new Error('Rate limit exceeded');
}
```

### checkRateLimit Helper

```typescript
import { checkRateLimit } from '@amtarc/auth-utils/security/rate-limit';

const result = await checkRateLimit({
  storage,
  key: 'api:user-123',
  max: 100,
  window: 60000,
  algorithm: 'token-bucket',
  capacity: 150
});

if (!result.allowed) {
  res.status(429).json({
    error: 'Too Many Requests',
    retryAfter: result.retryAfter,
    limit: result.limit,
    remaining: result.remaining
  });
}
```

## Brute Force Protection

### Account Lockout

```typescript
import { BruteForceProtection } from '@amtarc/auth-utils/security/rate-limit';

const bruteForce = new BruteForceProtection({
  storage: new MemoryRateLimitStorage(),
  maxAttempts: 5,
  lockoutDuration: 3600000 // 1 hour lockout in milliseconds
});

// Record failed login attempt
try {
  await login(username, password);
} catch (error) {
  const result = await bruteForce.recordFailedAttempt(username);
  
  if (!result.allowed) {
    throw new Error(`Account locked until ${new Date(result.lockedUntil!)}. Retry in ${result.retryAfter} seconds`);
  }
  
  throw new Error(`Invalid credentials. ${result.attemptsRemaining} attempts remaining`);
}

// Reset on successful login
await bruteForce.recordSuccessfulAttempt(username);
```

### IP-Based Protection

```typescript
// Protect by IP address
const ipProtection = new BruteForceProtection({
  storage,
  maxAttempts: 10,
  lockoutDuration: 1800000 // 30 minute lockout
});

// Before processing request
const check = await ipProtection.checkAttempt(req.ip);
if (!check.allowed) {
  res.status(429).json({
    error: 'Too many requests from this IP',
    unlockAt: check.lockedUntil,
    retryAfter: check.retryAfter
  });
  return;
}
```

### Combined Protection

```typescript
// Protect by both username and IP
async function checkBruteForce(username: string, ip: string) {
  const [usernameCheck, ipCheck] = await Promise.all([
    bruteForceByUsername.checkAttempt(username),
    bruteForceByIP.checkAttempt(ip)
  ]);
  
  if (!usernameCheck.allowed) {
    throw new Error(`Account locked. Try again at ${new Date(usernameCheck.lockedUntil!)}`);
  }
  
  if (!ipCheck.allowed) {
    throw new Error(`IP blocked. Try again at ${new Date(ipCheck.lockedUntil!)}`);
  }
}

// On failed login
await Promise.all([
  bruteForceByUsername.recordFailedAttempt(username),
  bruteForceByIP.recordFailedAttempt(ip)
]);

// On successful login
await Promise.all([
  bruteForceByUsername.recordSuccessfulAttempt(username),
  bruteForceByIP.recordSuccessfulAttempt(ip)
]);
```

## Security Headers

### Basic Security Headers

```typescript
import { createSecurityHeaders } from '@amtarc/auth-utils/security/headers';

const headers = createSecurityHeaders({
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  xFrameOptions: 'DENY',
  xContentTypeOptions: true,
  xDownloadOptions: true,
  xPermittedCrossDomainPolicies: 'none',
  referrerPolicy: 'strict-origin-when-cross-origin',
  xDnsPrefetchControl: false
});

// Apply to response
Object.entries(headers).forEach(([key, value]) => {
  res.setHeader(key, value);
});
```

### Content Security Policy (CSP)

```typescript
import { CSPBuilder } from '@amtarc/auth-utils/security/headers';

// Strict CSP
const csp = new CSPBuilder()
  .defaultSrc("'self'")
  .scriptSrc("'self'", "'unsafe-inline'", 'https://cdn.example.com')
  .styleSrc("'self'", "'unsafe-inline'")
  .imgSrc("'self'", 'data:', 'https:')
  .fontSrc("'self'", 'https://fonts.googleapis.com')
  .connectSrc("'self'", 'https://api.example.com')
  .frameAncestors("'none'")
  .baseUri("'self'")
  .formAction("'self'")
  .upgradeInsecureRequests()
  .build();

res.setHeader('Content-Security-Policy', csp);
```

### Complete CSPBuilder API

```typescript
const csp = new CSPBuilder()
  // Source directives
  .defaultSrc("'self'")
  .scriptSrc("'self'", "'unsafe-inline'")
  .styleSrc("'self'", "'unsafe-inline'")
  .imgSrc("'self'", 'data:', 'https:')
  .fontSrc("'self'")
  .connectSrc("'self'")
  .frameSrc("'none'")
  .frameAncestors("'none'")
  .formAction("'self'")
  .baseUri("'self'")
  .objectSrc("'none'")
  .mediaSrc("'self'")
  .workerSrc("'self'")
  .manifestSrc("'self'")
  
  // Reporting
  .reportUri('/csp-violation-report')
  .reportTo('csp-endpoint')
  
  // Security features
  .upgradeInsecureRequests()
  .blockAllMixedContent()
  .sandbox('allow-forms', 'allow-scripts')
  
  // Trusted Types (for XSS protection)
  .requireTrustedTypesFor('script')
  .trustedTypes('default', 'my-policy')
  
  .build();
```

### CSP Preset Policies

```typescript
import { CSPBuilder } from '@amtarc/auth-utils/security/headers';

// Strict policy (production)
const strictCSP = CSPBuilder.strict();
// Equivalent to:
// default-src 'none'; script-src 'self'; style-src 'self'; 
// img-src 'self' data:; font-src 'self'; connect-src 'self';
// frame-src 'none'; object-src 'none'; base-uri 'self';
// form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests

// Relaxed policy (development)
const relaxedCSP = CSPBuilder.relaxed();
// Allows unsafe-inline and unsafe-eval for easier development
```

### CSP with Nonces

```typescript
import { generateSecureToken } from '@amtarc/auth-utils/security/encryption';

// Generate nonce for each request
const nonce = generateSecureToken({ length: 16, encoding: 'base64' });

const csp = new CSPBuilder()
  .defaultSrc("'self'")
  .scriptSrc("'self'", `'nonce-${nonce}'`)
  .build();

res.setHeader('Content-Security-Policy', csp);

// Use nonce in scripts
const html = `
  <script nonce="${nonce}">
    console.log('This script is allowed');
  </script>
`;
```

### Security Headers Builder

```typescript
import { SecurityHeadersBuilder } from '@amtarc/auth-utils/security/headers';

const builder = new SecurityHeadersBuilder({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameOptions: 'DENY',
  contentTypeOptions: true,
  referrerPolicy: 'strict-origin-when-cross-origin',
  permissionsPolicy: {
    geolocation: [],
    microphone: [],
    camera: []
  }
});

// Add or remove headers
builder.addHeader('Custom-Header', 'value');
builder.removeHeader('X-Powered-By');

const headers = builder.getHeaders();

// Apply headers
Object.entries(headers).forEach(([key, value]) => {
  res.setHeader(key, value);
});
```

### Security Headers Presets

```typescript
import { SecurityHeadersBuilder } from '@amtarc/auth-utils/security/headers';

// Secure preset (production)
const secureHeaders = SecurityHeadersBuilder.secure().getHeaders();
// Includes strict CSP, HSTS, frame options, CORP, COEP, COOP, etc.

// Relaxed preset (development)
const devHeaders = SecurityHeadersBuilder.relaxed().getHeaders();
// Less restrictive for easier local development
```

## Encryption

### AES-256-GCM Encryption

```typescript
import { encrypt, decrypt } from '@amtarc/auth-utils/security/encryption';

const secret = 'your-32-byte-secret-key-here!!';
const data = { userId: '123', email: 'user@example.com' };

// Encrypt
const encrypted = await encrypt(data, secret, {
  algorithm: 'aes-256-gcm',
  encoding: 'base64'
});

console.log(encrypted);
// {
//   ciphertext: 'base64-encrypted-data',
//   iv: 'base64-iv',
//   authTag: 'base64-auth-tag',
//   algorithm: 'aes-256-gcm',
//   keyDerivation: 'none'
// }

// Decrypt
const decrypted = await decrypt(encrypted, secret);
console.log(decrypted); // { userId: '123', email: 'user@example.com' }
```

### String Encryption (Simplified)

```typescript
import { encryptToString, decryptFromString } from '@amtarc/auth-utils/security/encryption';

const secret = 'your-secret-key';
const data = 'sensitive-data';

// Encrypt to single base64 string
const encrypted = await encryptToString(data, secret);
console.log(encrypted); // 'eyJjaXBoZXJ0ZXh0Ijoi...'

// Decrypt
const decrypted = await decryptFromString(encrypted, secret);
console.log(decrypted); // 'sensitive-data'
```

### Key Derivation

```typescript
import { deriveKey, deriveKeyPBKDF2, deriveKeyScrypt } from '@amtarc/auth-utils/security/encryption';

// PBKDF2 (default)
const key1 = await deriveKey('user-password', {
  algorithm: 'pbkdf2',
  iterations: 100000,
  saltLength: 32,
  keyLength: 32
});

// Scrypt (more secure, slower)
const key2 = await deriveKeyScrypt('user-password', {
  cost: 16384,
  blockSize: 8,
  parallelization: 1,
  saltLength: 32,
  keyLength: 32
});

// Use derived key for encryption
const encrypted = await encrypt(data, key1.key);
```

### Export/Import Derived Keys

```typescript
import { exportDerivedKey, parseDerivedKey } from '@amtarc/auth-utils/security/encryption';

const derived = await deriveKey('password');

// Export for storage
const exported = exportDerivedKey(derived);
console.log(exported); // 'pbkdf2:100000:salt:key'

// Import later
const imported = parseDerivedKey(exported);

// Use imported key
const encrypted = await encrypt(data, imported.key);
```

## CSRF Helper Functions

### Low-Level Token Operations

```typescript
import { 
  generateCSRFToken,
  generateCSRFTokenPair,
  hashCSRFToken,
  validateCSRFToken,
  validateTimestampedToken,
  extractCSRFToken
} from '@amtarc/auth-utils/security/csrf';

// Generate a single CSRF token
const token = generateCSRFToken({
  length: 32,
  includeTimestamp: true,
  lifetime: 3600000
});

// Generate token pair for double-submit pattern
const { token, hashedToken } = generateCSRFTokenPair({
  length: 32,
  includeTimestamp: false
});

// Hash a CSRF token
const hash = hashCSRFToken(token);

// Validate CSRF token against storage
const result = await validateCSRFToken(submittedToken, {
  storage: csrfStorage,
  key: 'csrf:session-123',
  deleteAfterUse: true,
  strict: false
});

if (!result.valid) {
  console.error('CSRF validation failed:', result.reason);
}

// Validate timestamped token
const timestampResult = validateTimestampedToken(token, 3600000); // 1 hour max age

// Extract CSRF token from various sources
const extracted = extractCSRFToken({
  body: { _csrf: 'token' },
  headers: { 'x-csrf-token': 'token2' },
  query: { csrf: 'token3' }
}, {
  bodyField: '_csrf',
  headerName: 'x-csrf-token',
  queryField: 'csrf'
});
```

## Random Generation

### Secure Tokens

```typescript
import { generateSecureToken } from '@amtarc/auth-utils/security/encryption';

// Generate session token
const sessionToken = generateSecureToken({
  length: 32,
  encoding: 'base64'
});

// Generate API key
const apiKey = generateSecureToken({
  length: 32,
  encoding: 'hex',
  prefix: 'sk_'
});
console.log(apiKey); // 'sk_a1b2c3d4...'
```

### UUIDs

```typescript
import { generateUUID } from '@amtarc/auth-utils/security/encryption';

const id = generateUUID();
console.log(id); // '550e8400-e29b-41d4-a716-446655440000'
```

### Random Strings

```typescript
import { 
  generateRandomString, 
  generateRandomAlphanumeric,
  generateRandomInt 
} from '@amtarc/auth-utils/security/encryption';

// Custom charset
const code = generateRandomString(6, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789');
console.log(code); // 'A3K9XZ'

// Alphanumeric
const alphanumeric = generateRandomAlphanumeric(16);
console.log(alphanumeric); // 'aB3xK9mP2qR7sT4v'

// Random integer
const otp = generateRandomInt(100000, 999999);
console.log(otp); // 456789
```

## Integration Examples

### Complete API Protection

```typescript
import { createRateLimiter, BruteForceProtection } from '@amtarc/auth-utils/security/rate-limit';
import { generateSynchronizerToken, validateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
import { createSecurityHeaders } from '@amtarc/auth-utils/security/headers';
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';

const storage = new UniversalMemoryStorage();

// Rate limiting
const apiLimiter = createRateLimiter({
  storage,
  max: 1000,
  window: 3600000
});

// Brute force protection
const bruteForce = new BruteForceProtection({
  storage,
  maxAttempts: 5,
  windowMs: 900000,
  blockDurationMs: 3600000
});

// Request handler
async function handleRequest(req, res) {
  // 1. Apply security headers
  const headers = createSecurityHeaders({
    hsts: { maxAge: 31536000 },
    xFrameOptions: 'DENY'
  });
  Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));
  
  // 2. Check rate limit
  const rateLimit = await apiLimiter(req.userId);
  if (!rateLimit.allowed) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  
  // 3. Check brute force
  const bruteForceCheck = await bruteForce.checkAttempt(req.ip);
  if (!bruteForceCheck.allowed) {
    return res.status(429).json({ 
      error: 'Too many failed attempts',
      retryAfter: bruteForceCheck.retryAfter
    });
  }
  
  // 4. Validate CSRF for state-changing operations
  if (req.method === 'POST') {
    const csrfValid = await validateSynchronizerToken(req.body.csrf, {
      session: req.session,
      storage
    });
    
    if (!csrfValid.valid) {
      await bruteForce.recordFailedAttempt(req.ip);
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }
  
  // Process request...
}
```

## Best Practices

### CSRF Protection
1. Use synchronizer tokens for traditional web apps
2. Use double-submit for APIs and SPAs
3. Always validate on state-changing operations
4. Set appropriate token lifetimes
5. Implement token rotation on sensitive actions
6. Use SameSite cookies as additional protection

### Rate Limiting
1. Use sliding window counter for balanced performance
2. Implement multiple rate limits (per-user, per-IP)
3. Return clear error messages with retry information
4. Monitor rate limit violations
5. Set appropriate limits based on endpoint sensitivity
6. Consider token bucket for APIs allowing bursts

### Security Headers
1. Enable HSTS with includeSubDomains and preload
2. Use strict CSP with nonces for scripts
3. Set X-Frame-Options to DENY or SAMEORIGIN
4. Enable X-Content-Type-Options
5. Set restrictive Referrer-Policy
6. Implement Permissions-Policy for sensitive features

### Encryption
1. Use AES-256-GCM for authenticated encryption
2. Derive keys with PBKDF2 or Scrypt
3. Never reuse IVs
4. Store encrypted data with IV and auth tag
5. Rotate encryption keys periodically
6. Use constant-time comparison for tokens

## Related Documentation

- [Storage & Integration](./storage.md) - Unified storage adapters
- [Session Management](./sessions.md) - Session lifecycle
- [Guards](./guards.md) - Route protection
- [API Reference](/api/core.md#security) - Complete security API
