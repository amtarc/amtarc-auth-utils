# Changelog

All notable changes to `@amtarc/auth-utils` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.1] - 2026-02-14

### Changed
- Updated README documentation to reflect Phase 3 features and improvements
- Updated bundle size information (10.63 KB with all Phase 3 features)
- Improved API examples with correct function names and usage patterns
- Added comprehensive Phase 3 API reference (CSRF, rate limiting, encryption, headers)

## [1.2.0] - 2026-02-13

### Added

**Security Package (Phase 3):**

**CSRF Protection:**
- Token generation with configurable length and timestamps
- Double-submit cookie pattern for stateless protection
- Synchronizer token pattern with server-side validation
- Session-based and memory storage adapters
- `SessionCSRFAdapter` for session integration
- Timing-safe token comparison to prevent timing attacks

**Rate Limiting:**
- Token Bucket algorithm (allows bursts, maintains average rate)
- Fixed Window algorithm (simple counter with fixed reset intervals)
- Sliding Window Log algorithm (precise tracking)
- Sliding Window Counter algorithm (optimal balance)
- Brute-force protection with progressive delays and lockout
- Memory storage adapter with TTL support
- Atomic increment/decrement operations

**Security Headers:**
- CSP Builder with type-safe directive configuration
- Support for all CSP directives (default-src, script-src, etc.)
- Security headers collection (HSTS, X-Frame-Options, etc.)
- Permissions-Policy, COEP, COOP, CORP support
- Preset configurations: strict (production), relaxed (development)
- Method chaining for builder pattern

**Encryption:**
- AES-256-GCM encryption/decryption with authentication
- Key derivation: PBKDF2 (100k iterations) and Scrypt (16384 cost)
- Additional Authenticated Data (AAD) support
- Random generation: bytes, strings, UUIDs, secure tokens
- String format encryption (iv.authTag.ciphertext)
- Export/parse functionality for derived keys

**Storage Infrastructure:**
- `BaseStorage` interface with get, set, delete, exists
- `CounterStorage` interface with increment, decrement
- `UniversalMemoryStorage` adapter for all modules
- TTL support with automatic cleanup
- User session indexing for multi-device management
- Works across sessions, CSRF, and rate limiting modules

### Security Fixes
- Fixed CSRF token validation to prevent timestamp bypass attacks
- Added HTML attribute escaping to prevent XSS in token helpers
- Fixed ESM compatibility issues with dynamic imports
- Added error handling for malformed cookie encoding
- Added resource leak prevention with unref() on cleanup intervals

## [1.1.0] - 2026-02-11

### Added

**Session Management Enhancements:**
- Storage adapter pattern with `SessionStorageAdapter` interface
- `MemoryStorageAdapter` with automatic cleanup and TTL support
- `refreshSession()` with timestamp updates and ID rotation
- `invalidateSession()` for session termination
- Multi-device session management (`listUserSessions`, `revokeDeviceSession`, `enforceConcurrentSessionLimit`)
- Session fingerprinting (`generateSessionFingerprint`, `validateFingerprint`)
- `generateSessionId()` with cryptographic security

**Guards & Route Protection (New Module):**
- `requireAuth()` and `requireGuest()` authentication guards
- Composable guards (`requireAny`, `requireAll`, `composeGuards`)
- Redirect management (`isValidRedirect`, `saveAuthRedirect`, `restoreAuthRedirect`)
- Open redirect prevention
- Optional fingerprint validation in guards

**Cookie Management (New Module):**
- `createCookie()` and `parseCookie()` (RFC 6265 compliant)
- `signCookie()` and `verifyCookie()` with HMAC-SHA256
- `encryptCookie()` and `decryptCookie()` with AES-256-GCM
- `deleteCookie()` and `rotateCookie()` utilities
- Secure defaults (HttpOnly, Secure, SameSite)

**Error Handling (New Module):**
- 17 specialized error classes with HTTP status codes
- `AuthUtilsError` base class with error codes and timestamps
- Type guards (`isAuthUtilsError`, `getErrorStatusCode`, `serializeError`)
- Authentication errors (10): `UnauthenticatedError`, `UnauthorizedError`, etc.
- Session errors (4): `SessionNotFoundError`, `SessionExpiredError`, etc.
- Validation errors (3): `ValidationError`, `InvalidInputError`, `MissingFieldError`

**Package Structure:**
- 5 tree-shakeable entry points (`.`, `./session`, `./guards`, `./cookies`, `./errors`)
- ESM and CommonJS builds with TypeScript declarations

### Changed
- Centralized error system (moved to `errors/` module)
- Enhanced TypeScript strictness with `exactOptionalPropertyTypes`
- Optimized build output with code splitting
- Updated package description and keywords

### Tests
- **375 total tests** (100% passing, >95% coverage)
- 21 test files covering all modules

### Bundle Size
- Main: 2.01 KB | Session: 603 B | Guards: 393 B | Cookies: 708 B | Errors: 686 B
- **Total: ~4.4 KB** (tree-shakeable)

## [1.0.1] - 2026-02-10

### Added
- Initial public release
- Core session management (`createSession`, `validateSession`, `requireSession`)
- Basic error classes (`AuthError`, `SessionExpiredError`, etc.)
- TypeScript support with generics
- Framework-agnostic design
- Zero runtime dependencies

### Infrastructure
- Monorepo with Turborepo and pnpm
- TypeScript strict mode
- tsup build system
- Vitest testing
- CI/CD with GitHub Actions

### Tests
- 15 tests across 3 files (100% passing)

### Bundle Size
- ESM: 452 B | CJS: 1.84 KB

[1.1.0]: https://github.com/amtarc/amtarc-auth-utils/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/amtarc/amtarc-auth-utils/releases/tag/v1.0.1

