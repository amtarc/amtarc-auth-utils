# Changelog

All notable changes to `@amtarc/auth-utils` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.0] - 2026-02-16

### Added

**Authorization Package - Phase 4.2-4.4 (ABAC, Resource-Based, Guards):**

**ABAC (Attribute-Based Access Control):**
- `PolicyEngine` with policy evaluation, caching (5min default TTL), and combining algorithms
  - Three combining algorithms: deny-overrides (default), allow-overrides, first-applicable
  - Policy caching with configurable TTL and manual cache management
  - Support for policy versioning with automatic version increment
- `RuleEvaluator` with recursive rule evaluation and attribute path resolution
  - Support for AND, OR, NOT logical operators
  - Nested rule groups with unlimited depth
  - Attribute reference resolution with `${attribute.path}` syntax
- 13 comparison operators for flexible attribute matching:
  - Equality: `eq`, `neq`
  - Numeric: `gt`, `gte`, `lt`, `lte`
  - Array membership: `in`, `notIn`
  - String/Array contains: `contains`, `notContains`
  - String patterns: `startsWith`, `endsWith`, `matches` (regex)
- Four built-in attribute providers:
  - `UserAttributeProvider` - User attributes (id, role, department, permissions, metadata)
  - `ResourceAttributeProvider` - Resource attributes (id, type, ownerId, status, createdAt, metadata)
  - `EnvironmentAttributeProvider` - Context attributes (currentTime, dayOfWeek, hour, ipAddress, userAgent)
  - `CustomAttributeProvider` - Extensible for domain-specific attributes
- `MemoryPolicyStorage` with filtering by effect, resourceType, and action
- 39 comprehensive tests for operators, rule evaluation, and policy engine

**Resource-Based Access Control:**
- `ResourceManager` with full CRUD operations and permission management
  - Grant/revoke access with optional expiration timestamps
  - Check resource access with action-based filtering
  - Transfer ownership with audit trailing (grantedBy tracking)
  - List user resources and resource users with optional filtering
  - Automatic permission cleanup on resource deletion
- Nine standard resource actions:
  - `CREATE`, `READ`, `UPDATE`, `DELETE` - Basic CRUD operations
  - `ADMIN` - Full administrative access
  - `SHARE` - Share resources with others
  - `COMMENT` - Add comments/feedback
  - `DOWNLOAD` - Download resource content
  - `EXECUTE` - Run/execute resources
- Five pre-built ownership patterns:
  - `createFullOwnerAccess` - Complete control (all actions)
  - `createReadWriteOwner` - Modify but not delete (READ, UPDATE, SHARE, COMMENT)
  - `createReadOnlyOwner` - View only (READ, DOWNLOAD)
  - `createTeamBasedAccess` - Team membership validation
  - `createOrganizationAccess` - Organization membership validation
- Permission scopes: `own`, `team`, `organization`, `all`
- `MemoryResourceStorage` with user and resource indexing
- `createCustomOwnershipRule` for domain-specific ownership logic
- 21 comprehensive tests for resource manager and ownership patterns

**Unified Authorization Guards:**
- Eight guard functions for declarative access control:
  - `requirePermission` - RBAC permission checking
  - `requireRole` - RBAC role validation
  - `requirePolicy` - ABAC policy evaluation
  - `requireResourceAccess` - Resource-based access control
  - `requireOwnership` - Resource ownership validation
  - `combineGuardsAnd` - Combine guards with AND logic (all must pass)
  - `combineGuardsOr` - Combine guards with OR logic (any can pass)
  - `createCustomGuard` - Create domain-specific validators
- Composable guard system with context merging
- Specific error throwing (InsufficientPermissionError, InsufficientRoleError, ResourceAccessDeniedError)
- Type-safe guard contexts with TypeScript generics
- 21 comprehensive tests for all guard types and combinations

**New Exports:**
- `@amtarc/auth-utils/authorization/abac` - Complete ABAC module
- `@amtarc/auth-utils/authorization/resource` - Resource-based access control
- `@amtarc/auth-utils/authorization/guards` - Unified authorization guards

### Tests
- **768 total tests** (100% passing) - Added 81 new tests
  - ABAC: 39 tests (operators, rule evaluator, policy engine)
  - Resource: 21 tests (resource manager, ownership patterns)
  - Guards: 21 tests (all guard types, composition, error handling)

### Documentation
- Updated authorization guide header to include ABAC, Resource-based, and Guards
- Added TypeScript type exports for all new modules
- Comprehensive inline documentation with JSDoc comments

## [1.3.1] - 2026-02-16

### Fixed
- **Breaking:** Renamed `AuthorizationError` to `RBACAuthorizationError` to avoid naming conflicts with the main `AuthorizationError` class in `@amtarc/auth-utils/errors`
  - All RBAC-specific error classes now extend `RBACAuthorizationError`
  - Updated imports: use `RBACAuthorizationError` from `@amtarc/auth-utils/authorization/types`
- Fixed reverse index bugs in `MemoryRBACStorage` that could cause incorrect user role lookups
- Removed non-existent `checkExpiration` option from documentation

### Changed
- Optimized RBAC functional API performance with manager instance caching
  - Eliminates repeated object allocations in `rbac-manager.ts` functions
  - Cached instances: `cachedPermissionManager`, `cachedRoleManager`, `cachedGuards`
  - Automatic cache invalidation when default storage changes

### Added
- Comprehensive test coverage for RBAC error classes (8 new tests, 669 total)
  - `RoleNotFoundError` (2 tests)
  - `PermissionNotFoundError` (2 tests)
  - `RoleExistsError` (2 tests)
  - `PermissionExistsError` (2 tests)
- Added `@amtarc/auth-utils/authorization/types` subpath export for type-only imports

### Documentation
- Updated API reference with `RBACAuthorizationError` naming convention
- Added explanatory note in authorization guide about naming conflict avoidance
- Synchronized all error class documentation with implementation

## [1.3.0] - 2026-02-15

### Added

**Authorization Package (Phase 4):**

**RBAC (Role-Based Access Control):**
- `PermissionManager` with CRUD operations and auto-ID generation
- `RoleManager` with user assignment, permission granting, and permission inheritance
- `RoleHierarchy` validator with circular dependency detection (up to 10 levels)
- `MemoryRBACStorage` adapter with expiration and automatic cleanup
- `RBACGuards` with comprehensive permission and role checking
- Support for scoped role assignments (tenant, organization, project)
- Permission inheritance through role hierarchies with circular dependency prevention
- Expiring role assignments with automatic cleanup
- Batch operations for permissions and roles
- Type-safe permission and role IDs with automatic ID generation from names

**Authorization Types:**
- `UserId`, `ResourceId`, `AuthorizationResult`, `AuthorizationContext`
- `Role`, `Permission`, `UserRole` interfaces
- `RBACStorageAdapter` interface for custom storage implementations
- `RoleOptions`, `PermissionCheckOptions`, `HierarchyValidation` configuration types
- Authorization-specific error classes (imported via `@amtarc/auth-utils/authorization/types`)

**New Exports:**
- `@amtarc/auth-utils/authorization` - Complete authorization package
- `@amtarc/auth-utils/authorization/rbac` - RBAC submodule

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

