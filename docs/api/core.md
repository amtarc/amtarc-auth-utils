# @amtarc/auth-utils API Reference

Complete API reference for the core authentication utilities package.

## Installation

```bash
npm install @amtarc/auth-utils
```

## Import Paths

```typescript
// Main exports (all features)
import { createSession, requireAuth } from '@amtarc/auth-utils';

// Module-specific exports
import { 
  createSession,
  validateSession,
  refreshSession,
  invalidateSession
} from '@amtarc/auth-utils/session';

import { 
  requireAuth, 
  requireGuest, 
  requireAny 
} from '@amtarc/auth-utils/guards';

import { 
  createAuthCookie, 
  signCookie,
  encryptCookie 
} from '@amtarc/auth-utils/cookies';

import { 
  UnauthenticatedError,
  SessionExpiredError,
  isAuthUtilsError 
} from '@amtarc/auth-utils/errors';

// Storage Module (Phase 3)
import {
  UniversalMemoryStorage,
  BaseStorage,
  CounterStorage
} from '@amtarc/auth-utils/storage';

// Security Module (Phase 3)
import {
  generateCSRFToken,
  validateSynchronizerToken,
  createRateLimiter,
  BruteForceProtection,
  encrypt,
  decrypt,
  CSPBuilder,
  createSecurityHeaders
} from '@amtarc/auth-utils/security';
```

---

## Session Management

### createSession

Create a new session for a user.

```typescript
function createSession<TUser extends User = User>(
  user: TUser,
  options?: SessionOptions
): Session<TUser>
```

**Parameters:**
- `user`: User object with at least an `id` property
- `options`: Session configuration options

**Options:**
```typescript
interface SessionOptions {
  expiresIn?: number;      // Session lifetime in milliseconds
  absoluteTimeout?: number; // Absolute max lifetime
  renewalTimeout?: number;  // Auto-renewal threshold
}
```

**Returns:** `Session<TUser>` object

**Example:**
```typescript
const session = createSession(
  { id: 'user-123', email: 'user@example.com' },
  { expiresIn: 1000 * 60 * 60 * 24 }
);
```

### validateSession

Validate a session's expiration and timeouts.

```typescript
function validateSession<TUser extends User = User>(
  session: Session<TUser>
): ValidationResult
```

**Returns:** 
```typescript
interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'absolute-timeout-exceeded';
  needsRenewal: boolean;
}
```

**Example:**
```typescript
const result = validateSession(session);
if (!result.valid) {
  throw new SessionExpiredError(result.reason);
}
```

### requireSession

Create a session-protected handler.

```typescript
function requireSession<TUser extends User = User, TResult = unknown>(
  getSession: () => Session<TUser> | null | Promise<Session<TUser> | null>,
  handler: SessionHandler<TUser, TResult>,
  options?: SessionOptions
): () => Promise<TResult>
```

**Type:**
```typescript
type SessionHandler<TUser extends User = User, TResult = unknown> = (
  session: Session<TUser>
) => TResult | Promise<TResult>;
```

**Example:**
```typescript
const protectedHandler = requireSession(
  () => getSessionFromRequest(req),
  async (session) => {
    return { userId: session.user.id };
  }
);
```

### refreshSession

Refresh a session, extending its expiration.

```typescript
function refreshSession<TUser extends User = User>(
  session: Session<TUser>,
  storage: SessionStorageAdapter<TUser>,
  options?: RefreshSessionOptions
): Promise<Session<TUser>>
```

**Options:**
```typescript
interface RefreshSessionOptions {
  rotateId?: boolean;    // Generate new session ID
  expiresIn?: number;    // New expiration time
}
```

**Example:**
```typescript
const refreshed = await refreshSession(session, storage, {
  rotateId: true,
  expiresIn: 1000 * 60 * 60 * 24
});
```

### rotateSessionId

Rotate a session ID for security.

```typescript
function rotateSessionId<TUser extends User = User>(
  session: Session<TUser>,
  storage: SessionStorageAdapter<TUser>
): Promise<Session<TUser>>
```

### generateSessionId

Generate a cryptographically secure session ID.

```typescript
function generateSessionId(length?: number): string
```

**Parameters:**
- `length`: Length of ID in bytes (default: 32)

### invalidateSession

Delete a session from storage.

```typescript
function invalidateSession<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  sessionId: string,
  options?: InvalidateOptions
): Promise<void>
```

**Options:**
```typescript
interface InvalidateOptions {
  reason?: string;       // Reason for invalidation
  notifyUser?: boolean;  // Send notification
}
```

### invalidateUserSessions

Delete all sessions for a user.

```typescript
function invalidateUserSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  options?: InvalidateUserSessionsOptions
): Promise<void>
```

**Options:**
```typescript
interface InvalidateUserSessionsOptions extends InvalidateOptions {
  except?: string; // Session ID to keep
}
```

### invalidateAllSessions

Delete all sessions across all users.

```typescript
function invalidateAllSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>
): Promise<void>
```

### listUserSessions

Get all sessions for a user.

```typescript
function listUserSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  options?: ListUserSessionsOptions
): Promise<SessionInfo[]>
```

**Options:**
```typescript
interface ListUserSessionsOptions {
  sortBy?: 'createdAt' | 'expiresAt';
  order?: 'asc' | 'desc';
}
```

**Returns:**
```typescript
interface SessionInfo {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  deviceInfo?: FingerprintMetadata;
}
```

### countUserSessions

Count active sessions for a user.

```typescript
function countUserSessions<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string
): Promise<number>
```

### revokeDeviceSession

Revoke a specific device session.

```typescript
function revokeDeviceSession<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  deviceId: string
): Promise<void>
```

### enforceConcurrentSessionLimit

Enforce maximum concurrent sessions limit.

```typescript
function enforceConcurrentSessionLimit<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  maxSessions: number
): Promise<void>
```

### findSessionByDevice

Find a session by device fingerprint.

```typescript
function findSessionByDevice<TUser extends User = User>(
  storage: SessionStorageAdapter<TUser>,
  userId: string,
  deviceFingerprint: string
): Promise<Session<TUser> | null>
```

---

## Session Fingerprinting

### generateSessionFingerprint

Generate a session fingerprint from metadata.

```typescript
function generateSessionFingerprint(
  metadata: FingerprintMetadata
): string
```

**Metadata:**
```typescript
interface FingerprintMetadata {
  userAgent?: string;
  ip?: string;
  acceptLanguage?: string;
  platform?: string;
  [key: string]: string | undefined;
}
```

**Returns:** SHA-256 hash string

**Example:**
```typescript
const fingerprint = generateSessionFingerprint({
  userAgent: req.headers['user-agent'],
  ip: req.ip,
  acceptLanguage: req.headers['accept-language']
});
```

### validateFingerprint

Validate a session fingerprint.

```typescript
function validateFingerprint<TUser extends User = User>(
  session: Session<TUser>,
  currentMetadata: FingerprintMetadata,
  options?: FingerprintValidationOptions
): boolean
```

**Options:**
```typescript
interface FingerprintValidationOptions {
  strict?: boolean;        // Throw error on mismatch
  allowMissing?: boolean;  // Allow sessions without fingerprints
  message?: string;        // Custom error message
}
```

### compareFingerprints

Compare two fingerprints for equality (constant-time).

```typescript
function compareFingerprints(
  fingerprint1: string | undefined,
  fingerprint2: string | undefined
): boolean
```

### extractFingerprintMetadata

Extract fingerprint metadata from a request object.

```typescript
function extractFingerprintMetadata(
  request: {
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  },
  overrides?: Partial<FingerprintMetadata>
): FingerprintMetadata
```

---

## Storage Adapters

### SessionStorageAdapter

Interface for session storage implementations.

```typescript
interface SessionStorageAdapter<T = unknown> {
  get(sessionId: string): Promise<SessionEntry<T> | null>;
  set(sessionId: string, entry: SessionEntry<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
  
  // Optional methods
  getAllForUser?(userId: string): Promise<SessionEntry<T>[]>;
  deleteAllForUser?(userId: string): Promise<void>;
  count?(): Promise<number>;
}
```

**Session Entry:**
```typescript
interface SessionEntry<T = unknown> {
  sessionId: string;
  userId: string;
  data: T;
  createdAt: number;
  expiresAt: number;
  metadata?: Record<string, unknown>;
}
```

### MemoryStorageAdapter

Built-in memory storage with automatic cleanup.

```typescript
class MemoryStorageAdapter<T = unknown> implements SessionStorageAdapter<T> {
  constructor(options?: MemoryStorageOptions);
  
  get(sessionId: string): Promise<SessionEntry<T> | null>;
  set(sessionId: string, entry: SessionEntry<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
  getAllForUser(userId: string): Promise<SessionEntry<T>[]>;
  deleteAllForUser(userId: string): Promise<void>;
  count(): Promise<number>;
  getStats(): MemoryStorageStats;
  destroy(): void;
}
```

**Options:**
```typescript
interface MemoryStorageOptions {
  cleanupInterval?: number; // Cleanup interval in ms (default: 5 minutes)
  maxSize?: number;         // Maximum sessions to store
}
```

**Stats:**
```typescript
interface MemoryStorageStats {
  totalSessions: number;
  expiredSessions: number;
  activeSessions: number;
  userSessions: Map<string, number>;
}
```

---

## Authorization & RBAC

Role-Based Access Control system with permissions, role hierarchy, and access guards.

### Setup

#### setDefaultRBACStorage

Configure the default storage adapter for RBAC operations.

```typescript
function setDefaultRBACStorage(storage: RBACStorageAdapter): void
```

**Example:**
```typescript
import { setDefaultRBACStorage, MemoryRBACStorage } from '@amtarc/auth-utils';

const storage = new MemoryRBACStorage();
setDefaultRBACStorage(storage);
```

### Permission Management

#### definePermission

Define a new permission.

```typescript
function definePermission(
  permission: Omit<Permission, 'id'> & { id?: PermissionId }
): Promise<Permission>
```

**Parameters:**
```typescript
interface Permission {
  id: PermissionId;
  name: string;
  description?: string;
  resourceType?: string;
  actions?: string[];
  metadata?: Record<string, unknown>;
}
```

**Example:**
```typescript
await definePermission({
  id: 'posts:delete',
  name: 'Delete Posts',
  description: 'Allows deleting blog posts',
  resourceType: 'post',
  actions: ['delete']
});
```

#### definePermissions

Define multiple permissions at once.

```typescript
function definePermissions(
  permissions: Array<Omit<Permission, 'id'> & { id?: PermissionId }>
): Promise<Permission[]>
```

**Example:**
```typescript
await definePermissions([
  { id: 'posts:create', name: 'Create Posts' },
  { id: 'posts:update', name: 'Update Posts' },
  { id: 'posts:delete', name: 'Delete Posts' }
]);
```

#### updatePermission

Update an existing permission.

```typescript
function updatePermission(
  id: PermissionId,
  updates: Partial<Omit<Permission, 'id'>>
): Promise<Permission>
```

#### deletePermission

Delete a permission.

```typescript
function deletePermission(id: PermissionId): Promise<void>
```

#### getPermission

Get permission by ID.

```typescript
function getPermission(id: PermissionId): Promise<Permission | null>
```

#### listPermissions

List all defined permissions.

```typescript
function listPermissions(): Promise<Permission[]>
```

### Role Management

#### defineRole

Define a new role.

```typescript
function defineRole(
  role: Omit<Role, 'permissions' | 'parents' | 'createdAt' | 'updatedAt'> & {
    permissions?: string[];
    parents?: string[];
  }
): Promise<Role>
```

**Parameters:**
```typescript
interface Role {
  id: RoleId;
  name: string;
  description?: string;
  permissions: Set<PermissionId>;
  parents?: Set<RoleId>;
  metadata?: Record<string, unknown>;
  createdAt?: number;
  updatedAt?: number;
}
```

**Example:**
```typescript
await defineRole({
  id: 'editor',
  name: 'Editor',
  description: 'Can create and edit content',
  parents: new Set(['user']) // Inherits from 'user' role
});
```

#### updateRole

Update an existing role.

```typescript
function updateRole(
  id: RoleId,
  updates: Partial<Omit<Role, 'id' | 'permissions'>>
): Promise<Role>
```

#### deleteRole

Delete a role.

```typescript
function deleteRole(id: RoleId): Promise<void>
```

#### getRole

Get role by ID.

```typescript
function getRole(id: RoleId): Promise<Role | null>
```

#### listRoles

List all defined roles.

```typescript
function listRoles(): Promise<Role[]>
```

### Role-Permission Management

#### grantPermission

Grant a single permission to a role.

```typescript
function grantPermission(
  roleId: RoleId,
  permissionId: PermissionId
): Promise<void>
```

**Example:**
```typescript
await grantPermission('editor', 'posts:create');
```

#### grantPermissions

Grant multiple permissions to a role.

```typescript
function grantPermissions(
  roleId: RoleId,
  permissionIds: PermissionId[]
): Promise<void>
```

**Example:**
```typescript
await grantPermissions('editor', [
  'posts:create',
  'posts:update',
  'posts:read'
]);
```

#### revokePermission

Revoke a permission from a role.

```typescript
function revokePermission(
  roleId: RoleId,
  permissionId: PermissionId
): Promise<void>
```

#### getRolePermissions

Get all permissions for a role.

```typescript
function getRolePermissions(
  roleId: RoleId,
  options?: RoleOptions
): Promise<Set<PermissionId>>
```

**Options:**
```typescript
interface RoleOptions {
  includeInherited?: boolean; // Include permissions from parent roles
  maxDepth?: number;          // Max hierarchy depth to traverse
  checkExpiration?: boolean;  // Check role assignment expiration
}
```

**Example:**
```typescript
// Get direct permissions only
const directPerms = await getRolePermissions('editor');

// Get all permissions including inherited
const allPerms = await getRolePermissions('editor', {
  includeInherited: true
});
```

### User-Role Assignment

#### assignRole

Assign a role to a user.

```typescript
function assignRole(
  userId: UserId,
  roleId: RoleId,
  options?: {
    expiresAt?: number;
    scope?: string;
    metadata?: Record<string, unknown>;
  }
): Promise<void>
```

**Example:**
```typescript
// Basic assignment
await assignRole('user-123', 'editor');

// With expiration
await assignRole('user-456', 'admin', {
  expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
});

// With scope (multi-tenant)
await assignRole('user-789', 'admin', {
  scope: 'org:acme-corp'
});
```

#### removeRole

Remove a role from a user.

```typescript
function removeRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<void>
```

**Example:**
```typescript
// Remove global role
await removeRole('user-123', 'editor');

// Remove scoped role
await removeRole('user-123', 'admin', 'org:acme-corp');
```

#### getUserRoles

Get all role assignments for a user.

```typescript
function getUserRoles(userId: UserId): Promise<UserRole[]>
```

**Returns:**
```typescript
interface UserRole {
  userId: UserId;
  roleId: RoleId;
  assignedAt: number;
  expiresAt?: number;
  scope?: string;
  metadata?: Record<string, unknown>;
}
```

### Role Checks

#### hasRole

Check if user has a specific role.

```typescript
function hasRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<boolean>
```

**Example:**
```typescript
const isAdmin = await hasRole('user-123', 'admin');

const isOrgAdmin = await hasRole('user-123', 'admin', 'org:acme');
```

#### hasAnyRole

Check if user has any of the specified roles.

```typescript
function hasAnyRole(
  userId: UserId,
  roleIds: RoleId[],
  scope?: string
): Promise<boolean>
```

**Example:**
```typescript
const isStaff = await hasAnyRole('user-123', ['admin', 'moderator', 'editor']);
```

#### hasAllRoles

Check if user has all specified roles.

```typescript
function hasAllRoles(
  userId: UserId,
  roleIds: RoleId[],
  scope?: string
): Promise<boolean>
```

### Permission Checks

#### hasPermission

Check if user has a specific permission.

```typescript
function hasPermission(
  userId: UserId,
  permissionId: PermissionId,
  options?: PermissionCheckOptions
): Promise<boolean>
```

**Options:**
```typescript
interface PermissionCheckOptions {
  mode?: 'AND' | 'OR';        // For multiple permissions
  includeInherited?: boolean;  // Include inherited permissions
  scope?: string;              // Check within specific scope
}
```

**Example:**
```typescript
const canDelete = await hasPermission('user-123', 'posts:delete');

const canDeleteInOrg = await hasPermission('user-123', 'posts:delete', {
  scope: 'org:acme',
  includeInherited: true
});
```

#### hasAnyPermission

Check if user has any of the specified permissions.

```typescript
function hasAnyPermission(
  userId: UserId,
  permissionIds: PermissionId[],
  options?: PermissionCheckOptions
): Promise<boolean>
```

**Example:**
```typescript
const canModify = await hasAnyPermission('user-123', [
  'posts:update',
  'posts:delete'
]);
```

#### hasAllPermissions

Check if user has all specified permissions.

```typescript
function hasAllPermissions(
  userId: UserId,
  permissionIds: PermissionId[],
  options?: PermissionCheckOptions
): Promise<boolean>
```

#### requirePermission

Require user to have a permission (throws if unauthorized).

```typescript
function requirePermission(
  userId: UserId,
  permissionId: PermissionId,
  options?: PermissionCheckOptions
): Promise<void>
```

**Throws:** `InsufficientPermissionError` if user lacks permission

**Example:**
```typescript
try {
  await requirePermission('user-123', 'posts:delete');
  // User is authorized
} catch (error) {
  if (error instanceof InsufficientPermissionError) {
    console.error('Access denied:', error.code); // 'INSUFFICIENT_PERMISSION'
  }
}
```

#### requireRole

Require user to have a role (throws if unauthorized).

```typescript
function requireRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<void>
```

**Throws:** `InsufficientRoleError` if user lacks role

### Storage Adapters

#### MemoryRBACStorage

In-memory RBAC storage implementation.

```typescript
class MemoryRBACStorage implements RBACStorageAdapter {
  constructor();
  
  // Implements all RBACStorageAdapter methods
  getRole(roleId: RoleId): Promise<Role | null>;
  saveRole(role: Role): Promise<void>;
  deleteRole(roleId: RoleId): Promise<void>;
  listRoles(): Promise<Role[]>;
  
  getPermission(permissionId: PermissionId): Promise<Permission | null>;
  savePermission(permission: Permission): Promise<void>;
  deletePermission(permissionId: PermissionId): Promise<void>;
  listPermissions(): Promise<Permission[]>;
  
  getUserRoles(userId: UserId): Promise<UserRole[]>;
  assignUserRole(assignment: UserRole): Promise<void>;
  removeUserRole(userId: UserId, roleId: RoleId, scope?: string): Promise<void>;
  listUsersByRole(roleId: RoleId): Promise<UserId[]>;
}
```

**Example:**
```typescript
import { MemoryRBACStorage, setDefaultRBACStorage } from '@amtarc/auth-utils';

const storage = new MemoryRBACStorage();
setDefaultRBACStorage(storage);
```

#### RBACStorageAdapter

Interface for custom RBAC storage implementations.

```typescript
interface RBACStorageAdapter {
  // Role operations
  getRole(roleId: RoleId): Promise<Role | null>;
  saveRole(role: Role): Promise<void>;
  deleteRole(roleId: RoleId): Promise<void>;
  listRoles(): Promise<Role[]>;

  // Permission operations
  getPermission(permissionId: PermissionId): Promise<Permission | null>;
  savePermission(permission: Permission): Promise<void>;
  deletePermission(permissionId: PermissionId): Promise<void>;
  listPermissions(): Promise<Permission[]>;

  // User-role assignments
  getUserRoles(userId: UserId): Promise<UserRole[]>;
  assignUserRole(assignment: UserRole): Promise<void>;
  removeUserRole(userId: UserId, roleId: RoleId, scope?: string): Promise<void>;
  listUsersByRole(roleId: RoleId): Promise<UserId[]>;
}
```

### Class-Based API (Advanced)

For advanced use cases, manager classes provide more control.

#### PermissionManager

```typescript
class PermissionManager {
  constructor(options: { storage: RBACStorageAdapter });
  
  definePermission(permission: Omit<Permission, 'id'> & { id?: PermissionId }): Promise<Permission>;
  definePermissions(permissions: Array<Omit<Permission, 'id'> & { id?: PermissionId }>): Promise<Permission[]>;
  updatePermission(id: PermissionId, updates: Partial<Omit<Permission, 'id'>>): Promise<Permission>;
  deletePermission(id: PermissionId): Promise<void>;
  getPermission(id: PermissionId): Promise<Permission | null>;
  listPermissions(): Promise<Permission[]>;
}
```

#### RoleManager

```typescript
class RoleManager {
  constructor(options: { storage: RBACStorageAdapter });
  
  defineRole(role: Omit<Role, 'permissions' | 'parents' | 'createdAt' | 'updatedAt'> & { permissions?: string[]; parents?: string[] }): Promise<Role>;
  updateRole(id: RoleId, updates: Partial<Omit<Role, 'id' | 'permissions' | 'parents'>> & { permissions?: string[]; parents?: string[] }): Promise<Role>;
  deleteRole(id: RoleId): Promise<void>;
  getRole(id: RoleId): Promise<Role | null>;
  listRoles(): Promise<Role[]>;
  
  grantPermission(roleId: RoleId, permissionId: PermissionId): Promise<void>;
  grantPermissions(roleId: RoleId, permissionIds: PermissionId[]): Promise<void>;
  revokePermission(roleId: RoleId, permissionId: PermissionId): Promise<void>;
  getRolePermissions(roleId: RoleId, options?: RoleOptions): Promise<Set<PermissionId>>;
  
  assignRole(userId: UserId, roleId: RoleId, options?: { expiresAt?: number; scope?: string; metadata?: Record<string, unknown> }): Promise<void>;
  removeRole(userId: UserId, roleId: RoleId, scope?: string): Promise<void>;
  getUserRoles(userId: UserId): Promise<UserRole[]>;
  
  hasRole(userId: UserId, roleId: RoleId, scope?: string): Promise<boolean>;
  hasAnyRole(userId: UserId, roleIds: RoleId[], scope?: string): Promise<boolean>;
  hasAllRoles(userId: UserId, roleIds: RoleId[], scope?: string): Promise<boolean>;
}
```

#### RoleHierarchy

```typescript
class RoleHierarchy {
  constructor(options: { storage: RBACStorageAdapter; maxDepth?: number });
  
  validateHierarchy(roleId: RoleId): Promise<HierarchyValidation>;
  validateAll(): Promise<HierarchyValidation>;
  calculateDepth(roleId: RoleId): Promise<number>;
  getAncestors(roleId: RoleId): Promise<Set<RoleId>>;
  getDescendants(roleId: RoleId): Promise<Set<RoleId>>;
  getAllPermissions(roleId: RoleId, maxDepth?: number): Promise<Set<PermissionId>>;
}
```

**Types:**
```typescript
interface HierarchyValidation {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
}
```

#### RBACGuards

```typescript
class RBACGuards {
  constructor(options: {
    roleManager: RoleManager;
    throwOnFailure?: boolean;
    onError?: (error: Error, context: RBACGuardContext) => void | Promise<void>;
  });
  
  hasPermission(userId: UserId, permissionId: PermissionId, options?: PermissionCheckOptions): Promise<boolean>;
  requirePermission(context: { userId: UserId; scope?: string }, permissionId: PermissionId, options?: PermissionCheckOptions): Promise<void>;
  requireRole(context: { userId: UserId; scope?: string }, roleId: RoleId): Promise<void>;
}
```

**Factory function:**
```typescript
function createRBACGuards(options: {
  roleManager: RoleManager;
  throwOnFailure?: boolean;
  onError?: (error: Error, context: RBACGuardContext) => void | Promise<void>;
}): RBACGuards
```

### Authorization Errors

All authorization error classes extend `AuthorizationError`.

#### AuthorizationError

```typescript
class AuthorizationError extends Error {
  constructor(
    message: string,
    code: string,
    context?: Record<string, unknown>
  );
  
  readonly code: string;
  readonly context?: Record<string, unknown>;
}
```

#### InsufficientRoleError

Thrown when user lacks required role.

```typescript
class InsufficientRoleError extends AuthorizationError {
  constructor(required: string | string[], context?: Record<string, unknown>);
  
  readonly code: 'INSUFFICIENT_ROLE';
}
```

#### InsufficientPermissionError

Thrown when user lacks required permission.

```typescript
class InsufficientPermissionError extends AuthorizationError {
  constructor(required: string | string[], context?: Record<string, unknown>);
  
  readonly code: 'INSUFFICIENT_PERMISSION';
}
```

#### RoleNotFoundError

Thrown when a role doesn't exist.

```typescript
class RoleNotFoundError extends AuthorizationError {
  constructor(roleId: string, context?: Record<string, unknown>);
  
  readonly code: 'ROLE_NOT_FOUND';
}
```

#### PermissionNotFoundError

Thrown when a permission doesn't exist.

```typescript
class PermissionNotFoundError extends AuthorizationError {
  constructor(permissionId: string, context?: Record<string, unknown>);
  
  readonly code: 'PERMISSION_NOT_FOUND';
}
```

#### RoleExistsError

Thrown when attempting to create duplicate role.

```typescript
class RoleExistsError extends AuthorizationError {
  constructor(roleId: string, context?: Record<string, unknown>);
  
  readonly code: 'ROLE_EXISTS';
}
```

#### PermissionExistsError

Thrown when attempting to create duplicate permission.

```typescript
class PermissionExistsError extends AuthorizationError {
  constructor(permissionId: string, context?: Record<string, unknown>);
  
  readonly code: 'PERMISSION_EXISTS';
}
```

#### ResourceAccessDeniedError

Thrown when access to a resource is denied.

```typescript
class ResourceAccessDeniedError extends AuthorizationError {
  constructor(
    resourceId: ResourceId,
    action: string,
    context?: Record<string, unknown>
  );
  
  readonly code: 'RESOURCE_ACCESS_DENIED';
}
```

**Import authorization errors:**
```typescript
import {
  InsufficientRoleError,
  InsufficientPermissionError,
  RoleNotFoundError,
  PermissionNotFoundError,
  RoleExistsError,
  PermissionExistsError,
  ResourceAccessDeniedError
} from '@amtarc/auth-utils/authorization/types';
```

---

## Guards & Route Protection

### requireAuth

Require authenticated user.

```typescript
function requireAuth<T = unknown>(
  options: RequireAuthOptions
): GuardFunction<T>
```

**Options:**
```typescript
interface RequireAuthOptions {
  storage: SessionStorageAdapter;
  getSessionId: (context: GuardContext) => Promise<string | undefined>;
  onSuccess: (context: GuardContext) => Promise<unknown>;
  onFailure: (context: GuardContext) => Promise<unknown>;
  validateFingerprint?: boolean;
  fingerprintMetadata?: (context: GuardContext) => FingerprintMetadata;
}
```

**Example:**
```typescript
const guard = requireAuth({
  storage,
  getSessionId: async (ctx) => ctx.request?.cookies?.session,
  onSuccess: async (ctx) => ({ userId: ctx.session.userId }),
  onFailure: async () => ({ error: 'Unauthorized' })
});
```

### requireGuest

Require unauthenticated user.

```typescript
function requireGuest(
  options: RequireGuestOptions
): GuardFunction
```

**Options:**
```typescript
interface RequireGuestOptions {
  storage?: SessionStorageAdapter;
  getSessionId?: (context: GuardContext) => Promise<string | undefined>;
  onSuccess: (context: GuardContext) => Promise<unknown>;
  onFailure?: (context: GuardContext) => Promise<unknown>;
}
```

### requireAny

Require at least one guard to pass (OR logic).

```typescript
function requireAny<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### requireAll

Require all guards to pass (AND logic).

```typescript
function requireAll<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### chainGuards

Execute guards sequentially.

```typescript
function chainGuards<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### allowAll

Always allow access.

```typescript
function allowAll<T = unknown>(data?: T): GuardFunction<T>
```

### denyAll

Always deny access.

```typescript
function denyAll(options?: {
  message?: string;
  statusCode?: number;
}): GuardFunction
```

### conditionalGuard

Execute guard based on condition.

```typescript
function conditionalGuard<T = unknown>(
  options: {
    condition: (context: GuardContext<T>) => Promise<boolean>;
    guardIfTrue: GuardFunction<T>;
    guardIfFalse: GuardFunction<T>;
  }
): GuardFunction<T>
```

### Guard Types

```typescript
type GuardFunction<T = unknown> = (
  context: GuardContext
) => Promise<GuardResult<T>>;

interface GuardContext {
  request?: unknown;
  session?: Session;
}

interface GuardResult<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  redirect?: string;
}
```

---

## Redirect Management

### isValidRedirect

Validate a redirect URL for security.

```typescript
function isValidRedirect(
  url: string,
  options?: RedirectValidationOptions
): boolean
```

**Options:**
```typescript
interface RedirectValidationOptions {
  allowedDomains?: string[];  // Allowed domains
  allowRelative?: boolean;    // Allow relative URLs
  allowSubdomains?: boolean;  // Allow subdomains
  maxLength?: number;         // Max URL length
}
```

### saveAuthRedirect

Save a redirect URL for after authentication.

```typescript
function saveAuthRedirect(
  storage: RedirectStorage,
  key: string,
  url: string,
  options?: SaveRedirectOptions
): Promise<void>
```

**Options:**
```typescript
interface SaveRedirectOptions extends RedirectValidationOptions {
  ttl?: number; // Time to live in milliseconds
}
```

### restoreAuthRedirect

Restore and remove a saved redirect URL.

```typescript
function restoreAuthRedirect(
  storage: RedirectStorage,
  key: string,
  options?: RestoreRedirectOptions
): Promise<string | null>
```

**Options:**
```typescript
interface RestoreRedirectOptions extends RedirectValidationOptions {
  fallback?: string; // Default URL if none saved
}
```

### peekAuthRedirect

View saved redirect without removing it.

```typescript
function peekAuthRedirect(
  storage: RedirectStorage,
  key: string
): Promise<string | null>
```

### clearAuthRedirect

Clear a saved redirect URL.

```typescript
function clearAuthRedirect(
  storage: RedirectStorage,
  key: string
): Promise<void>
```

**Redirect Storage:**
```typescript
interface RedirectStorage {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
}
```

---

## Cookie Management

### createAuthCookie

Create a cookie string with options.

```typescript
function createAuthCookie(
  name: string,
  value: string,
  options?: CookieOptions
): string
```

**Options:**
```typescript
interface CookieOptions {
  maxAge?: number;              // Max age in seconds
  expires?: Date;               // Expiration date
  path?: string;                // Cookie path
  domain?: string;              // Cookie domain
  secure?: boolean;             // Secure flag (HTTPS only)
  httpOnly?: boolean;           // HttpOnly flag
  sameSite?: 'strict' | 'lax' | 'none'; // SameSite policy
  partitioned?: boolean;        // Partitioned attribute (CHIPS)
}
```

**Example:**
```typescript
const cookie = createAuthCookie('session', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 60 * 60 * 24
});
```

### createAuthCookies

Create multiple cookies at once.

```typescript
function createAuthCookies(
  cookies: Array<{ name: string; value: string; options?: CookieOptions }>
): string[]
```

### parseAuthCookies

Parse all cookies from Cookie header.

```typescript
function parseAuthCookies(
  cookieHeader: string | undefined
): Record<string, string>
```

### getAuthCookie

Get a specific cookie value.

```typescript
function getAuthCookie(
  cookieHeader: string | undefined,
  name: string
): string | undefined
```

### hasAuthCookie

Check if a cookie exists.

```typescript
function hasAuthCookie(
  cookieHeader: string | undefined,
  name: string
): boolean
```

### parseSetCookie

Parse a Set-Cookie header.

```typescript
function parseSetCookie(setCookieHeader: string): ParsedCookie | null
```

**Returns:**
```typescript
interface ParsedCookie {
  name: string;
  value: string;
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned: boolean;
}
```

### Validation Functions

```typescript
function isValidCookieName(name: string): boolean
function isValidCookieValue(value: string): boolean
function estimateCookieSize(name: string, value: string, options?: CookieOptions): number
```

---

## Cookie Signing (HMAC)

### signCookie

Sign a cookie value with HMAC-SHA256.

```typescript
function signCookie(value: string, secret: string): string
```

**Example:**
```typescript
const signed = signCookie('session_123', 'your-secret-key');
// Returns: "session_123.signature"
```

### unsignCookie

Verify and extract value from signed cookie.

```typescript
function unsignCookie(
  signedValue: string | undefined,
  secret: string
): { valid: boolean; value?: string }
```

### verifyCookieSignature

Verify a cookie signature.

```typescript
function verifyCookieSignature(
  value: string,
  signature: string,
  secret: string
): boolean
```

### signAndCreateCookie

Sign and create a cookie in one step.

```typescript
function signAndCreateCookie(
  name: string,
  value: string,
  secret: string,
  options?: CookieOptions
): string
```

### unsignCookieStrict

Verify signed cookie, throw on failure.

```typescript
function unsignCookieStrict(
  signedValue: string,
  secret: string
): string
```

**Throws:** `CookieSignatureError`

```typescript
class CookieSignatureError extends Error {
  constructor(message: string);
}
```

---

## Cookie Encryption (AES-256-GCM)

### encryptCookie

Encrypt a cookie value with AES-256-GCM.

```typescript
function encryptCookie(value: string, secret: string): string
```

**Example:**
```typescript
const encrypted = encryptCookie('session_123', 'your-secret-key');
// Returns: "iv:authTag:ciphertext"
```

### decryptCookie

Decrypt an encrypted cookie value.

```typescript
function decryptCookie(
  encryptedValue: string | undefined,
  secret: string
): { valid: boolean; value?: string }
```

### verifyEncryptedCookie

Verify encrypted cookie can be decrypted.

```typescript
function verifyEncryptedCookie(
  encryptedValue: string,
  secret: string
): boolean
```

### encryptAndCreateCookie

Encrypt and create a cookie in one step.

```typescript
function encryptAndCreateCookie(
  name: string,
  value: string,
  secret: string,
  options?: CookieOptions
): string
```

### decryptCookieStrict

Decrypt cookie, throw on failure.

```typescript
function decryptCookieStrict(
  encryptedValue: string,
  secret: string
): string
```

**Throws:** `CookieDecryptionError`

```typescript
class CookieDecryptionError extends Error {
  constructor(message: string);
}
```

---

## Cookie Deletion

### deleteAuthCookie

Create a cookie deletion string.

```typescript
function deleteAuthCookie(
  name: string,
  options?: Partial<CookieOptions>
): string
```

### deleteAuthCookies

Delete multiple cookies.

```typescript
function deleteAuthCookies(
  names: string[],
  options?: Partial<CookieOptions>
): string[]
```

### deleteAuthCookieExact

Delete cookie with exact path and domain.

```typescript
function deleteAuthCookieExact(
  name: string,
  path: string,
  domain?: string
): string
```

### deleteAuthCookieAllPaths

Delete cookie from all possible paths.

```typescript
function deleteAuthCookieAllPaths(
  name: string,
  paths: string[],
  domain?: string
): string[]
```

---

## Cookie Rotation

### rotateCookie

Rotate a cookie value.

```typescript
function rotateCookie(
  name: string,
  oldValue: string,
  newValue: string,
  options?: CookieOptions
): CookieRotationResult
```

**Returns:**
```typescript
interface CookieRotationResult {
  oldCookie: string;  // Cookie to delete
  newCookie: string;  // New cookie to set
}
```

### rotateCookies

Rotate multiple cookies.

```typescript
function rotateCookies(
  rotations: Array<{
    name: string;
    oldValue: string;
    newValue: string;
    options?: CookieOptions;
  }>
): CookieRotationResult[]
```

### rotateSignedCookie

Rotate a signed cookie.

```typescript
function rotateSignedCookie(
  name: string,
  oldValue: string,
  newValue: string,
  secret: string,
  options?: CookieOptions
): CookieRotationResult
```

### rotateEncryptedCookie

Rotate an encrypted cookie.

```typescript
function rotateEncryptedCookie(
  name: string,
  oldValue: string,
  newValue: string,
  secret: string,
  options?: CookieOptions
): Promise<CookieRotationResult>
```

### shouldRotateCookie

Determine if a cookie should be rotated.

```typescript
function shouldRotateCookie(
  createdAt: number,
  rotationInterval: number
): boolean
```

---

## Error Handling

### Base Error Classes

```typescript
class AuthUtilsError extends Error {
  code: string;
  statusCode: number;
  isOperational: boolean;
  metadata?: Record<string, unknown>;
  timestamp: number;
  
  constructor(
    message: string,
    code: string,
    statusCode: number,
    metadata?: Record<string, unknown>
  );
  
  toJSON(): {
    code: string;
    message: string;
    statusCode: number;
    timestamp: number;
    metadata?: Record<string, unknown>;
  };
}

class AuthError extends AuthUtilsError {
  // Alias for AuthUtilsError
}
```

### Authentication Errors

```typescript
class UnauthenticatedError extends AuthUtilsError
  // HTTP 401 - User not authenticated

class AuthenticationError extends AuthUtilsError
  // HTTP 401 - Authentication failed

class AlreadyAuthenticatedError extends AuthUtilsError
  // HTTP 400 - User already authenticated

class InvalidTokenError extends AuthUtilsError
  // HTTP 401 - Invalid token

class FingerprintMismatchError extends AuthUtilsError
  // HTTP 401 - Session fingerprint mismatch
```

### Authorization Errors

```typescript
class UnauthorizedError extends AuthUtilsError
  // HTTP 403 - Insufficient permissions

class AuthorizationError extends AuthUtilsError
  // HTTP 403 - Authorization failed
```

### Session Errors

```typescript
class SessionNotFoundError extends AuthUtilsError {
  sessionId?: string;
  // HTTP 404 - Session not found
}

class SessionExpiredError extends AuthUtilsError
  // HTTP 401 - Session expired

class InvalidSessionError extends AuthUtilsError
  // HTTP 401 - Session invalid

class UnauthorizedSessionAccessError extends AuthUtilsError
  // HTTP 403 - Unauthorized session access
```

### Validation Errors

```typescript
class ValidationError extends AuthUtilsError {
  fields?: Record<string, string>;
  // HTTP 400 - Validation failed
}

class InvalidInputError extends AuthUtilsError
  // HTTP 400 - Invalid input

class MissingFieldError extends AuthUtilsError
  // HTTP 400 - Required field missing
```

### Security Errors

```typescript
class RateLimitError extends AuthUtilsError
  // HTTP 429 - Rate limit exceeded

class CSRFError extends AuthUtilsError
  // HTTP 403 - CSRF validation failed

class InvalidRedirectError extends AuthUtilsError
  // HTTP 400 - Invalid redirect URL
```

---

## Error Type Guards

### isAuthUtilsError

Check if error is an AuthUtilsError.

```typescript
function isAuthUtilsError(error: unknown): error is AuthUtilsError
```

### isOperationalError

Check if error is operational (expected).

```typescript
function isOperationalError(error: unknown): boolean
```

### isSessionError

Check if error is session-related.

```typescript
function isSessionError(
  error: unknown
): error is SessionNotFoundError 
  | SessionExpiredError 
  | InvalidSessionError 
  | UnauthorizedSessionAccessError
```

### isAuthenticationError

Check if error is authentication-related.

```typescript
function isAuthenticationError(
  error: unknown
): error is UnauthenticatedError | AuthenticationError
```

### isAuthorizationError

Check if error is authorization-related.

```typescript
function isAuthorizationError(
  error: unknown
): error is AuthorizationError
```

### isValidationError

Check if error is a validation error.

```typescript
function isValidationError(error: unknown): error is ValidationError
```

### Error Utilities

```typescript
function getErrorStatusCode(error: unknown): number
  // Get HTTP status code (500 for unknown errors)

function getErrorCode(error: unknown): string
  // Get error code ('INTERNAL_ERROR' for unknown)

function serializeError(error: unknown): {
  code: string;
  message: string;
  statusCode: number;
  timestamp: number;
  metadata?: Record<string, unknown>;
}
  // Serialize error to JSON
```

---

## TypeScript Types

### Core Types

```typescript
interface User {
  id: string;
  [key: string]: unknown;
}

interface Session<TUser extends User = User> {
  id: string;
  user: TUser;
  createdAt: Date;
  expiresAt: Date;
}

interface SessionOptions {
  expiresIn?: number;
  absoluteTimeout?: number;
  renewalTimeout?: number;
}

interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned?: boolean;
}
```

### Context Types

```typescript
interface RequestContext {
  headers?: Record<string, string | string[] | undefined>;
  method?: string;
  url?: string;
  ip?: string;
  [key: string]: unknown;
}

interface ResponseContext {
  statusCode?: number;
  headers?: Record<string, string>;
  [key: string]: unknown;
}
```

---

### createSession

Create a new session for a user.

```typescript
function createSession<T = unknown>(
  userId: string,
  options?: SessionOptions<T>
): Session<T>
```

**Parameters:**
- `userId`: User identifier
- `options`: Session configuration options

**Options:**
- `expiresIn`: Session lifetime in milliseconds
- `idleTimeout`: Idle timeout in milliseconds
- `absoluteTimeout`: Maximum session lifetime
- `data`: Custom session data
- `fingerprint`: Session fingerprint hash

**Returns:** `Session<T>` object

**Example:**
```typescript
const session = createSession('user-123', {
  expiresIn: 1000 * 60 * 60 * 24,
  data: { roles: ['admin'] }
});
```

### validateSession

Validate a session's expiration and timeouts.

```typescript
function validateSession<T = unknown>(
  session: Session<T>,
  options?: ValidationOptions
): ValidationResult
```

**Parameters:**
- `session`: Session to validate
- `options`: Validation options

**Options:**
- `idleTimeout`: Idle timeout in milliseconds
- `absoluteTimeout`: Absolute timeout in milliseconds
- `refreshThreshold`: Threshold for refresh suggestion (0-1)

**Returns:** 
```typescript
interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'idle-timeout' | 'absolute-timeout';
  shouldRefresh: boolean;
}
```

### refreshSession

Refresh a session, optionally rotating the session ID.

```typescript
async function refreshSession<T = unknown>(
  session: Session<T>,
  storage: SessionStorageAdapter<T>,
  options?: RefreshOptions
): Promise<Session<T>>
```

**Parameters:**
- `session`: Session to refresh
- `storage`: Storage adapter
- `options`: Refresh options

**Options:**
- `rotateId`: Generate new session ID (default: true)
- `expiresIn`: New expiration time in milliseconds

**Returns:** Refreshed `Session<T>` object

### invalidateSession

Delete a session from storage.

```typescript
async function invalidateSession<T = unknown>(
  storage: SessionStorageAdapter<T>,
  sessionId: string
): Promise<void>
```

### invalidateAllSessions

Delete all sessions for a user.

```typescript
async function invalidateAllSessions<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string
): Promise<void>
```

### Session Type

```typescript
interface Session<T = unknown> {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  lastActivityAt: number;
  data?: T;
  fingerprint?: string;
}
```

### SessionStorageAdapter

Interface for session storage implementations.

```typescript
interface SessionStorageAdapter<T = unknown> {
  get(sessionId: string): Promise<Session<T> | null>;
  set(sessionId: string, session: Session<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
}
```

### MemoryStorageAdapter

Built-in memory storage with automatic cleanup.

```typescript
class MemoryStorageAdapter<T = unknown> implements SessionStorageAdapter<T> {
  constructor(options?: MemoryStorageOptions);
  
  get(sessionId: string): Promise<Session<T> | null>;
  set(sessionId: string, session: Session<T>): Promise<void>;
  delete(sessionId: string): Promise<void>;
  cleanup(): Promise<void>;
  destroy(): void;
}

interface MemoryStorageOptions {
  cleanupInterval?: number; // Cleanup interval in ms
  maxSize?: number; // Maximum sessions to store
}
```

## Multi-Device Sessions

### addDeviceSession

Add a device session for a user.

```typescript
async function addDeviceSession<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string,
  sessionId: string,
  metadata: FingerprintMetadata,
  options?: DeviceSessionOptions
): Promise<DeviceSession>
```

**Parameters:**
- `storage`: Storage adapter
- `userId`: User identifier
- `sessionId`: Session identifier
- `metadata`: Device fingerprint metadata
- `options`: Device session options

**Options:**
- `maxDevices`: Maximum concurrent devices
- `trustDevice`: Mark device as trusted

**Returns:** `DeviceSession` object

### getActiveDevices

Get all active devices for a user.

```typescript
async function getActiveDevices<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string
): Promise<DeviceSession[]>
```

### revokeDevice

Revoke a specific device session.

```typescript
async function revokeDevice<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string,
  deviceId: string
): Promise<void>
```

### revokeAllDevicesExcept

Revoke all devices except the specified one.

```typescript
async function revokeAllDevicesExcept<T = unknown>(
  storage: SessionStorageAdapter<T>,
  userId: string,
  keepDeviceId: string
): Promise<void>
```

## Session Fingerprinting

### generateSessionFingerprint

Generate a session fingerprint from metadata.

```typescript
function generateSessionFingerprint(
  metadata: FingerprintMetadata
): string
```

**Parameters:**
- `metadata`: Fingerprint metadata

```typescript
interface FingerprintMetadata {
  userAgent?: string;
  ip?: string;
  acceptLanguage?: string;
  platform?: string;
  [key: string]: string | undefined;
}
```

**Returns:** SHA-256 hash string

### validateFingerprint

Validate a session fingerprint.

```typescript
function validateFingerprint<T = unknown>(
  session: Session<T>,
  currentMetadata: FingerprintMetadata,
  options?: FingerprintValidationOptions
): boolean
```

**Options:**
- `strict`: Throw error on mismatch
- `allowMissing`: Allow sessions without fingerprints
- `message`: Custom error message

### extractFingerprintMetadata

Extract fingerprint metadata from a request object.

```typescript
function extractFingerprintMetadata(
  request: {
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  },
  overrides?: Partial<FingerprintMetadata>
): FingerprintMetadata
```

## Guards

### requireAuth

Require authenticated user.

```typescript
function requireAuth<T = unknown>(
  options: RequireAuthOptions<T>
): GuardFunction<T>
```

**Options:**
```typescript
interface RequireAuthOptions<T = unknown> {
  storage: SessionStorageAdapter<T>;
  getSessionId: (context: GuardContext<T>) => Promise<string | undefined>;
  onSuccess: (context: GuardContext<T>) => Promise<unknown>;
  onFailure: (context: GuardContext<T>) => Promise<unknown>;
  validateFingerprint?: boolean;
  fingerprintMetadata?: (context: GuardContext<T>) => FingerprintMetadata;
}
```

### requireGuest

Require unauthenticated user.

```typescript
function requireGuest<T = unknown>(
  options: RequireGuestOptions<T>
): GuardFunction<T>
```

**Options:**
```typescript
interface RequireGuestOptions<T = unknown> {
  storage?: SessionStorageAdapter<T>;
  getSessionId?: (context: GuardContext<T>) => Promise<string | undefined>;
  onSuccess: (context: GuardContext<T>) => Promise<unknown>;
  onFailure?: (context: GuardContext<T>) => Promise<unknown>;
}
```

### requireAny

Require at least one guard to pass (OR logic).

```typescript
function requireAny<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### requireAll

Require all guards to pass (AND logic).

```typescript
function requireAll<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### chainGuards

Execute guards sequentially.

```typescript
function chainGuards<T = unknown>(
  guards: GuardFunction<T>[]
): GuardFunction<T>
```

### allowAll

Always allow access.

```typescript
function allowAll<T = unknown>(
  options: AllowAllOptions<T>
): GuardFunction<T>
```

### conditionalGuard

Execute guard based on condition.

```typescript
function conditionalGuard<T = unknown>(
  options: ConditionalGuardOptions<T>
): GuardFunction<T>
```

**Options:**
```typescript
interface ConditionalGuardOptions<T = unknown> {
  condition: (context: GuardContext<T>) => Promise<boolean>;
  guardIfTrue: GuardFunction<T>;
  guardIfFalse: GuardFunction<T>;
}
```

### redirect

Create a redirect response.

```typescript
function redirect(
  url: string,
  options?: RedirectOptions
): RedirectResult
```

**Options:**
- `query`: Query parameters to append
- `allowedDomains`: Allowed domains for redirect
- `allowRelative`: Allow relative URLs

### Guard Types

```typescript
type GuardFunction<T = unknown> = (
  context: GuardContext<T>
) => Promise<GuardResult<T>>;

interface GuardContext<T = unknown> {
  request?: unknown;
  session?: Session<T>;
}

type GuardResult<T = unknown> = unknown;
```

## Cookies

### createCookie

Create a cookie string.

```typescript
function createCookie(
  name: string,
  value: string,
  options?: CookieOptions
): string
```

**Options:**
```typescript
interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned?: boolean;
}
```

### parseCookie

Parse a cookie from Cookie header.

```typescript
function parseCookie(
  cookieHeader: string | undefined,
  name: string
): ParsedCookie | null
```

### parseCookies

Parse all cookies from Cookie header.

```typescript
function parseCookies(
  cookieHeader: string | undefined
): Record<string, string>
```

### getCookieValue

Get a cookie value from Cookie header.

```typescript
function getCookieValue(
  cookieHeader: string | undefined,
  name: string
): string | undefined
```

### signCookie

Sign a cookie with HMAC-SHA256.

```typescript
function signCookie(
  cookie: string,
  secret: string
): string
```

### verifyCookie

Verify a signed cookie.

```typescript
function verifyCookie(
  cookieHeader: string | undefined,
  name: string,
  secret: string,
  options?: VerifyOptions
): VerifyResult
```

**Returns:**
```typescript
interface VerifyResult {
  valid: boolean;
  value?: string;
  error?: string;
}
```

### encryptCookie

Encrypt a cookie with AES-256-GCM.

```typescript
async function encryptCookie(
  cookie: string,
  secret: string
): Promise<string>
```

### decryptCookie

Decrypt an encrypted cookie.

```typescript
async function decryptCookie(
  cookieHeader: string | undefined,
  name: string,
  secret: string,
  options?: DecryptOptions
): Promise<DecryptResult>
```

**Returns:**
```typescript
interface DecryptResult {
  valid: boolean;
  value?: string;
  error?: string;
}
```

### rotateCookie

Rotate a cookie value.

```typescript
function rotateCookie(
  cookie: string,
  newValue: string
): string
```

### deleteCookie

Create a cookie deletion string.

```typescript
function deleteCookie(
  name: string,
  options?: Partial<CookieOptions>
): string
```

### deleteAllCookies

Create deletion strings for multiple cookies.

```typescript
function deleteAllCookies(
  names: string[],
  options?: Partial<CookieOptions>
): string[]
```

## Errors

### Error Classes

```typescript
// Authentication Errors
class UnauthenticatedError extends AuthError
class InvalidCredentialsError extends AuthError
class AccountLockedError extends AuthError
class FingerprintMismatchError extends AuthError

// Session Errors
class SessionExpiredError extends AuthError
class SessionNotFoundError extends AuthError
class SessionRevokedError extends AuthError
class ConcurrentSessionError extends AuthError
class InvalidSessionError extends AuthError

// Cookie Errors
class InvalidCookieError extends AuthError
class CookieSignatureMismatchError extends AuthError
class CookieDecryptionError extends AuthError

// Token Errors
class InvalidTokenError extends AuthError
class TokenExpiredError extends AuthError
class TokenRevokedError extends AuthError

// Validation Errors
class ValidationError extends AuthError

// Authorization Errors
class UnauthorizedError extends AuthError
class ForbiddenError extends AuthError
class InsufficientPermissionsError extends AuthError
```

### Base Error Class

```typescript
class AuthError extends Error {
  code: string;
  statusCode: number;
  metadata?: Record<string, unknown>;
  timestamp: number;
  
  toJSON(): {
    code: string;
    message: string;
    statusCode: number;
    timestamp: number;
    metadata?: Record<string, unknown>;
  };
}
```

### Type Guards

```typescript
// General
function isAuthError(error: unknown): error is AuthError

// Authentication
function isAuthenticationError(error: unknown): boolean
function isUnauthenticatedError(error: unknown): error is UnauthenticatedError
function isInvalidCredentialsError(error: unknown): error is InvalidCredentialsError
function isAccountLockedError(error: unknown): error is AccountLockedError

// Session
function isSessionError(error: unknown): boolean
function isSessionExpiredError(error: unknown): error is SessionExpiredError
function isSessionNotFoundError(error: unknown): error is SessionNotFoundError
function isSessionRevokedError(error: unknown): error is SessionRevokedError

// Cookie
function isCookieError(error: unknown): boolean
function isInvalidCookieError(error: unknown): error is InvalidCookieError
function isCookieSignatureMismatchError(error: unknown): error is CookieSignatureMismatchError

// Token
function isTokenError(error: unknown): boolean
function isInvalidTokenError(error: unknown): error is InvalidTokenError
function isTokenExpiredError(error: unknown): error is TokenExpiredError

// Validation
function isValidationError(error: unknown): error is ValidationError

// Authorization
function isAuthorizationError(error: unknown): boolean
function isUnauthorizedError(error: unknown): error is UnauthorizedError
function isForbiddenError(error: unknown): error is ForbiddenError
```

## TypeScript Types

### Main Types

```typescript
// Sessions
interface Session<T = unknown> {
  sessionId: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  lastActivityAt: number;
  data?: T;
  fingerprint?: string;
}

interface SessionOptions<T = unknown> {
  expiresIn?: number;
  idleTimeout?: number;
  absoluteTimeout?: number;
  data?: T;
  fingerprint?: string;
}

interface ValidationResult {
  valid: boolean;
  reason?: 'expired' | 'idle-timeout' | 'absolute-timeout';
  shouldRefresh: boolean;
}

// Device Sessions
interface DeviceSession {
  deviceId: string;
  userId: string;
  sessionId: string;
  fingerprint: string;
  trusted: boolean;
  createdAt: number;
}

// Cookies
interface CookieOptions {
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure?: boolean;
  httpOnly?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned?: boolean;
}

interface ParsedCookie {
  name: string;
  value: string;
  maxAge?: number;
  expires?: Date;
  path?: string;
  domain?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  partitioned: boolean;
}

// Guards
type GuardFunction<T = unknown> = (
  context: GuardContext<T>
) => Promise<GuardResult<T>>;

interface GuardContext<T = unknown> {
  request?: unknown;
  session?: Session<T>;
}

type GuardResult<T = unknown> = unknown;
```


---

## Storage Module (Phase 3)

### BaseStorage Interface

Foundation interface for all storage adapters.

```typescript
interface BaseStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}
```

**Methods:**
- `get(key)`: Retrieve value by key, returns `null` if not found or expired
- `set(key, value, ttl?)`: Store value with optional TTL in milliseconds
- `delete(key)`: Remove value by key
- `exists(key)`: Check if key exists and is not expired

### CounterStorage Interface

Extends BaseStorage with counter operations for rate limiting.

```typescript
interface CounterStorage extends BaseStorage {
  increment(key: string, amount?: number): Promise<number>;
  decrement(key: string, amount?: number): Promise<number>;
}
```

**Methods:**
- `increment(key, amount?)`: Increment counter, returns new value
- `decrement(key, amount?)`: Decrement counter, returns new value

### UniversalMemoryStorage Class

Universal in-memory storage adapter for all modules (sessions, CSRF, rate limiting).

```typescript
class UniversalMemoryStorage implements CounterStorage {
  constructor(options?: { cleanupIntervalMs?: number });
  
  // BaseStorage methods
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown, ttl?: number | StorageOptions): Promise<void>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
  
  // CounterStorage methods
  increment(key: string, amount?: number): Promise<number>;
  decrement(key: string, amount?: number): Promise<number>;
  
  // Session-specific methods
  touch(sessionId: string, ttl: number): Promise<void>;
  getUserSessions(userId: string): Promise<string[]>;
  deleteUserSessions(userId: string): Promise<void>;
  cleanup(): Promise<number>;
  
  // Utility methods
  size(): number;
  clear(): void;
  destroy(): void;
}
```

**Constructor Options:**
```typescript
interface UniversalStorageOptions {
  cleanupIntervalMs?: number; // Auto-cleanup interval (default: 60000)
}
```

**Session-Specific Methods:**
- `touch(sessionId, ttl)`: Update session expiration without changing data
- `getUserSessions(userId)`: Get all session IDs for a user
- `deleteUserSessions(userId)`: Delete all sessions for a user
- `cleanup()`: Remove expired entries, returns count removed

**Utility Methods:**
- `size()`: Get total number of stored entries
- `clear()`: Remove all data
- `destroy()`: Stop cleanup interval and clear all data

**Example:**
```typescript
import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';

const storage = new UniversalMemoryStorage({
  cleanupIntervalMs: 60000 // Cleanup every minute
});

// Use with sessions
await storage.set('session:123', sessionData, 3600000); // 1 hour TTL

// Use with CSRF
await storage.set('csrf:abc', csrfToken, 1800000); // 30 min TTL

// Use with rate limiting
await storage.increment('ratelimit:user-123'); // Counter operations
```

---

## CSRF Protection 

### generateCSRFToken

Generate a CSRF token.

```typescript
function generateCSRFToken(options?: CSRFTokenOptions): string

interface CSRFTokenOptions {
  length?: number;              // Token length in bytes (default: 32)
  includeTimestamp?: boolean;   // Include timestamp (default: false)
  lifetime?: number;            // Token lifetime in ms
  charset?: 'base64' | 'hex' | 'alphanumeric'; // Character set
}
```

**Example:**
```typescript
const token = generateCSRFToken({
  length: 32,
  includeTimestamp: true,
  lifetime: 3600000
});
```

### generateCSRFTokenPair

Generate token pair for double-submit pattern.

```typescript
function generateCSRFTokenPair(options?: CSRFTokenOptions): {
  token: string;
  hashedToken: string;
}
```

### hashCSRFToken

Hash a CSRF token with SHA-256.

```typescript
function hashCSRFToken(token: string): string
```

### generateSynchronizerToken

Generate and store CSRF token (synchronizer pattern).

```typescript
async function generateSynchronizerToken(
  options: SynchronizerTokenOptions
): Promise<SynchronizerTokenResult>

interface SynchronizerTokenOptions {
  session: Session;
  storage: CSRFStorageAdapter;
  regenerate?: 'per-request' | 'per-session' | 'never';
  lifetime?: number; // Token lifetime in ms
}

interface SynchronizerTokenResult {
  token: string;
  sessionUpdated: boolean;
}
```

### validateSynchronizerToken

Validate CSRF token (synchronizer pattern).

```typescript
async function validateSynchronizerToken(
  token: string,
  options: {
    session: Session;
    storage: CSRFStorageAdapter;
    deleteAfterUse?: boolean;
    strict?: boolean;
  }
): Promise<{ valid: boolean; reason?: string }>
```

### generateDoubleSubmitToken

Generate CSRF token for double-submit pattern.

```typescript
function generateDoubleSubmitToken(
  options?: DoubleSubmitOptions
): DoubleSubmitResult

interface DoubleSubmitOptions {
  session?: Session;
  lifetime?: number;
  includeSession?: boolean;
}

interface DoubleSubmitResult {
  token: string;
  hashedToken: string;
}
```

### validateDoubleSubmitToken

Validate double-submit CSRF token.

```typescript
async function validateDoubleSubmitToken(
  token: string,
  options: {
    session?: Session;
    cookieToken: string;
    strict?: boolean;
  }
): Promise<{ valid: boolean; reason?: string }>
```

### validateCSRFToken

Low-level CSRF token validation.

```typescript
async function validateCSRFToken(
  token: string,
  options: ValidateCSRFTokenOptions
): Promise<CSRFValidationResult>

interface ValidateCSRFTokenOptions {
  storage: CSRFStorageAdapter;
  key: string;
  deleteAfterUse?: boolean;
  strict?: boolean;
}

interface CSRFValidationResult {
  valid: boolean;
  reason?: 'missing' | 'invalid' | 'expired' | 'mismatch';
}
```

### validateTimestampedToken

Validate CSRF token with timestamp.

```typescript
function validateTimestampedToken(
  token: string,
  maxAge: number
): { valid: boolean; age?: number; reason?: string }
```

### extractCSRFToken

Extract CSRF token from request.

```typescript
function extractCSRFToken(
  request: {
    body?: Record<string, unknown>;
    headers?: Record<string, unknown>;
    query?: Record<string, unknown>;
  },
  options?: {
    bodyField?: string;
    headerName?: string;
    queryField?: string;
  }
): string | null
```

### attachCSRFTokenToHTML

Auto-inject CSRF tokens into HTML forms.

```typescript
function attachCSRFTokenToHTML(
  html: string,
  token: string,
  options?: {
    formAttribute?: string;
    inputName?: string;
  }
): string
```

### CSRF Storage Adapters

```typescript
class MemoryCSRFStorage implements CSRFStorageAdapter {
  async get(key: string): Promise<string | null>;
  async set(key: string, token: string, ttl?: number): Promise<void>;
  async delete(key: string): Promise<void>;
  async exists(key: string): Promise<boolean>;
}

class SessionCSRFStorage implements CSRFStorageAdapter {
  constructor(getSession: () => Session);
  // Same interface as MemoryCSRFStorage
}

class SessionCSRFAdapter implements CSRFStorageAdapter {
  constructor(sessionStorage: SessionStorageAdapter, sessionId: string);
  // Stores CSRF tokens within session data
}
```

---

## Rate Limiting 

### createRateLimiter

Create a rate limiter with specified algorithm.

```typescript
function createRateLimiter(
  options: RateLimitOptions
): (key: string) => Promise<RateLimitResult>

interface RateLimitOptions {
  storage: RateLimitStorage;
  max: number;                  // Max requests
  window: number;               // Time window in ms
  algorithm?: 'fixed-window' | 'sliding-window-counter' | 
              'sliding-window-log' | 'token-bucket';
  keyPrefix?: string;           // Key prefix (default: 'ratelimit')
  capacity?: number;            // Token bucket capacity
  refillRate?: number;          // Token bucket refill rate
}

interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}
```

**Example:**
```typescript
const limiter = createRateLimiter({
  storage: new UniversalMemoryStorage(),
  max: 100,
  window: 60000, // 1 minute
  algorithm: 'sliding-window-counter'
});

const result = await limiter('user-123');
if (!result.allowed) {
  throw new Error(`Rate limit exceeded. Retry in ${result.retryAfter}ms`);
}
```

### checkRateLimit

Convenience function to check rate limit.

```typescript
async function checkRateLimit(
  key: string,
  options: RateLimitOptions
): Promise<RateLimitResult>
```

### fixedWindow

Fixed window rate limiting algorithm.

```typescript
function fixedWindow(
  key: string,
  options: { storage: RateLimitStorage; max: number; window: number }
): Promise<RateLimitResult>
```

### slidingWindowCounter

Sliding window counter algorithm (recommended).

```typescript
function slidingWindowCounter(
  key: string,
  options: { storage: RateLimitStorage; max: number; window: number }
): Promise<RateLimitResult>
```

### slidingWindowLog

Sliding window log algorithm (most accurate).

```typescript
function slidingWindowLog(
  key: string,
  options: { storage: RateLimitStorage; max: number; window: number }
): Promise<RateLimitResult>
```

### tokenBucket

Token bucket algorithm (allows bursts).

```typescript
function tokenBucket(
  key: string,
  options: {
    storage: RateLimitStorage;
    capacity: number;
    refillRate: number;
    window: number;
  }
): Promise<RateLimitResult>
```

### BruteForceProtection

Brute force attack protection with progressive delays.

```typescript
class BruteForceProtection {
  constructor(options: BruteForceOptions);
  
  checkAttempt(key: string): Promise<BruteForceResult>;
  recordFailedAttempt(key: string): Promise<BruteForceResult>;
  recordSuccessfulAttempt(key: string): Promise<void>;
  unlock(key: string): Promise<void>;
}

interface BruteForceOptions {
  storage?: RateLimitStorage;
  maxAttempts: number;          // Max attempts before lockout
  lockoutDuration: number;      // Lockout duration in ms
  delayMultiplier?: number;     // Progressive delay multiplier (default: 2)
  baseDelay?: number;           // Base delay in ms (default: 1000)
}

interface BruteForceResult {
  allowed: boolean;
  attemptsRemaining: number;
  lockedUntil?: number;         // Timestamp when unlocked
  retryAfter?: number;          // Seconds until retry
}
```

**Example:**
```typescript
const bruteForce = new BruteForceProtection({
  maxAttempts: 5,
  lockoutDuration: 3600000 // 1 hour
});

// Check before attempting
const check = await bruteForce.checkAttempt('user-123');
if (!check.allowed) {
  throw new Error(`Locked until ${new Date(check.lockedUntil!)}`);
}

// Record failed attempt
const result = await bruteForce.recordFailedAttempt('user-123');
if (!result.allowed) {
  console.log(`Account locked. ${result.attemptsRemaining} attempts remaining`);
}

// Reset on success
await bruteForce.recordSuccessfulAttempt('user-123');
```

### MemoryRateLimitStorage

In-memory storage for rate limiting.

```typescript
class MemoryRateLimitStorage implements RateLimitStorage {
  async get(key: string): Promise<unknown>;
  async set(key: string, value: unknown, ttl?: number): Promise<void>;
  async delete(key: string): Promise<void>;
  async exists(key: string): Promise<boolean>;
  async increment(key: string, amount?: number): Promise<number>;
  async decrement(key: string, amount?: number): Promise<number>;
}
```

---

## Encryption 

### encrypt

Encrypt data with AES-256-GCM.

```typescript
async function encrypt(
  data: unknown,
  secret: string | Buffer,
  options?: EncryptionOptions
): Promise<EncryptedData>

interface EncryptionOptions {
  algorithm?: 'aes-256-gcm' | 'aes-128-gcm';
  encoding?: 'base64' | 'hex';
}

interface EncryptedData {
  ciphertext: string;
  iv: string;
  authTag: string;
  algorithm: string;
  keyDerivation: string;
}
```

### decrypt

Decrypt data encrypted with AES-256-GCM.

```typescript
async function decrypt(
  encrypted: EncryptedData | string,
  secret: string | Buffer
): Promise<unknown>
```

### encryptToString

Encrypt data to a single base64 string.

```typescript
async function encryptToString(
  data: unknown,
  secret: string | Buffer,
  options?: EncryptionOptions
): Promise<string>
```

### decryptFromString

Decrypt data from a base64 string.

```typescript
async function decryptFromString(
  encrypted: string,
  secret: string | Buffer
): Promise<unknown>
```

### deriveKey

Derive encryption key from password.

```typescript
async function deriveKey(
  password: string | Buffer,
  options?: KeyDerivationOptions
): Promise<DerivedKey>

interface KeyDerivationOptions {
  algorithm?: 'pbkdf2' | 'scrypt';
  salt?: Buffer | string;
  saltLength?: number;          // Salt length in bytes (default: 32)
  keyLength?: number;           // Output key length (default: 32)
  iterations?: number;          // PBKDF2 iterations (default: 100000)
  cost?: number;                // Scrypt cost factor (default: 16384)
  blockSize?: number;           // Scrypt block size (default: 8)
  parallelization?: number;     // Scrypt parallelization (default: 1)
}

interface DerivedKey {
  key: Buffer;
  salt: Buffer;
  algorithm: 'pbkdf2' | 'scrypt';
  params: Record<string, number>;
}
```

### deriveKeyPBKDF2

Derive key using PBKDF2.

```typescript
async function deriveKeyPBKDF2(
  password: string | Buffer,
  options?: KeyDerivationOptions
): Promise<DerivedKey>
```

### deriveKeyScrypt

Derive key using Scrypt (more secure, slower).

```typescript
async function deriveKeyScrypt(
  password: string | Buffer,
  options?: KeyDerivationOptions
): Promise<DerivedKey>
```

### exportDerivedKey

Export derived key as string for storage.

```typescript
function exportDerivedKey(derived: DerivedKey): string
```

### parseDerivedKey

Parse exported derived key string.

```typescript
function parseDerivedKey(exported: string): DerivedKey
```

### generateRandomBytes

Generate cryptographically secure random bytes.

```typescript
function generateRandomBytes(size: number): Buffer
```

### generateRandomString

Generate random string with custom charset.

```typescript
function generateRandomString(length: number, charset?: string): string
```

### generateRandomAlphanumeric

Generate alphanumeric random string.

```typescript
function generateRandomAlphanumeric(length: number): string
```

### generateRandomInt

Generate random integer in range.

```typescript
function generateRandomInt(min: number, max: number): number
```

### generateUUID

Generate UUID v4.

```typescript
function generateUUID(): string
```

### generateSecureToken

Generate secure token with prefix and encoding.

```typescript
function generateSecureToken(options?: {
  length?: number;
  encoding?: 'base64' | 'hex';
  prefix?: string;
}): string
```

**Example:**
```typescript
// Encrypt sensitive data
const encrypted = await encrypt(
  { userId: '123', email: 'user@example.com' },
  'your-secret-key'
);

// Decrypt
const decrypted = await decrypt(encrypted, 'your-secret-key');

// Derive key from password
const derived = await deriveKey('user-password', {
  algorithm: 'scrypt',
  cost: 16384
});

// Generate secure tokens
const token = generateSecureToken({
  length: 32,
  encoding: 'base64',
  prefix: 'sk_'
});
```

---

## Security Headers 

### CSPBuilder

Content Security Policy builder.

```typescript
class CSPBuilder {
  constructor(options?: CSPOptions);
  
  // Directive methods
  defaultSrc(...sources: string[]): this;
  scriptSrc(...sources: string[]): this;
  styleSrc(...sources: string[]): this;
  imgSrc(...sources: string[]): this;
  fontSrc(...sources: string[]): this;
  connectSrc(...sources: string[]): this;
  frameSrc(...sources: string[]): this;
  frameAncestors(...sources: string[]): this;
  formAction(...sources: string[]): this;
  baseUri(...sources: string[]): this;
  objectSrc(...sources: string[]): this;
  mediaSrc(...sources: string[]): this;
  workerSrc(...sources: string[]): this;
  manifestSrc(...sources: string[]): this;
  
  // Reporting
  reportUri(...uris: string[]): this;
  reportTo(...groups: string[]): this;
  
  // Security features
  upgradeInsecureRequests(): this;
  blockAllMixedContent(): this;
  sandbox(...values: string[]): this;
  requireTrustedTypesFor(...values: string[]): this;
  trustedTypes(...policies: string[]): this;
  
  // Build methods
  build(): string;
  getHeaderName(): string;
  toHeader(): Record<string, string>;
  
  // Static presets
  static strict(): CSPBuilder;
  static relaxed(): CSPBuilder;
}
```

**Example:**
```typescript
import { CSPBuilder } from '@amtarc/auth-utils/security/headers';

// Custom CSP
const csp = new CSPBuilder()
  .defaultSrc("'self'")
  .scriptSrc("'self'", "'unsafe-inline'", 'https://cdn.example.com')
  .styleSrc("'self'", "'unsafe-inline'")
  .imgSrc("'self'", 'data:', 'https:')
  .upgradeInsecureRequests()
  .build();

// Or use presets
const strictCSP = CSPBuilder.strict(); // Production
const relaxedCSP = CSPBuilder.relaxed(); // Development
```

### SecurityHeadersBuilder

Security headers builder.

```typescript
class SecurityHeadersBuilder {
  constructor(options?: SecurityHeadersOptions);
  
  // Instance methods
  addHeader(name: string, value: string): this;
  removeHeader(name: string): this;
  getHeaders(): Record<string, string>;
  
  // Static presets
  static secure(): SecurityHeadersBuilder;
  static relaxed(): SecurityHeadersBuilder;
}

interface SecurityHeadersOptions {
  csp?: CSPBuilder | string;
  hsts?: {
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  frameOptions?: 'DENY' | 'SAMEORIGIN';
  contentTypeOptions?: boolean;
  xssProtection?: boolean | { mode?: 'block'; report?: string };
  referrerPolicy?: 'no-referrer' | 'no-referrer-when-downgrade' | 
                   'origin' | 'origin-when-cross-origin' | 
                   'same-origin' | 'strict-origin' | 
                   'strict-origin-when-cross-origin' | 'unsafe-url';
  permissionsPolicy?: Record<string, string[]>;
  crossOriginEmbedderPolicy?: 'require-corp' | 'credentialless';
  crossOriginOpenerPolicy?: 'same-origin' | 'same-origin-allow-popups' | 'unsafe-none';
  crossOriginResourcePolicy?: 'same-origin' | 'same-site' | 'cross-origin';
}
```

### createSecurityHeaders

Convenience function to create security headers.

```typescript
function createSecurityHeaders(
  options?: SecurityHeadersOptions
): Record<string, string>
```

**Example:**
```typescript
import { createSecurityHeaders, SecurityHeadersBuilder } from '@amtarc/auth-utils/security/headers';

// Quick creation
const headers = createSecurityHeaders({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  frameOptions: 'DENY',
  contentTypeOptions: true
});

// Or use builder
const builder = new SecurityHeadersBuilder({ /* options */ });
builder.addHeader('Custom-Header', 'value');
const customHeaders = builder.getHeaders();

// Or use presets
const secureHeaders = SecurityHeadersBuilder.secure().getHeaders();
const devHeaders = SecurityHeadersBuilder.relaxed().getHeaders();
```

---

## Additional Types

### Storage Types

```typescript
interface BaseStorage {
  get(key: string): Promise<unknown>;
  set(key: string, value: unknown, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}

interface CounterStorage extends BaseStorage {
  increment(key: string, amount?: number): Promise<number>;
  decrement(key: string, amount?: number): Promise<number>;
}

interface StorageOptions {
  ttl?: number;                 // TTL in seconds
  metadata?: Record<string, unknown>;
}
```

### CSRF Types

```typescript
interface CSRFStorageAdapter extends BaseStorage {
  get(key: string): Promise<string | null>;
  set(key: string, token: string, ttl?: number): Promise<void>;
  delete(key: string): Promise<void>;
  exists(key: string): Promise<boolean>;
}

interface CSRFProtectionOptions {
  storage: CSRFStorageAdapter;
  tokenLength?: number;
  lifetime?: number;
  regenerate?: 'per-request' | 'per-session' | 'never';
}
```

### Rate Limiting Types

```typescript
interface RateLimitStorage extends CounterStorage {}

interface RateLimitInfo {
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfter?: number;
}
```

---


## Related Documentation

- [Introduction](/guide/introduction)
- [Quick Start](/guide/quick-start)
- [Session Management](/guide/sessions)
- [Guards & Middleware](/guide/guards)
- [Cookies](/guide/cookies)
- [Error Handling](/guide/errors)
- [Security Features](/guide/security)
- [Storage & Integration](/guide/storage)
