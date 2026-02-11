# Changelog

All notable changes to `@amtarc/auth-utils` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

