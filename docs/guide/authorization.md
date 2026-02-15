# Authorization & RBAC

Complete guide to Role-Based Access Control (RBAC) with permissions, role hierarchy, and access guards.

## Overview

The authorization module provides enterprise-grade RBAC features:

- **Role Management**: Define roles with hierarchical inheritance
- **Permission System**: Granular permission definitions and assignments
- **User-Role Assignment**: Flexible role assignment with scoped access
- **Access Guards**: Declarative permission and role checking
- **Functional API**: Simple, stateless functions (recommended)
- **Class-Based API**: Advanced control with managers (optional)
- **Storage Adapters**: Pluggable storage backends (Memory included)

## Quick Start

### Setup Storage

```typescript
import { setDefaultRBACStorage, MemoryRBACStorage } from '@amtarc/auth-utils';

// Initialize storage (once at app startup)
const storage = new MemoryRBACStorage();
setDefaultRBACStorage(storage);
```

### Define Permissions

```typescript
import { definePermission, definePermissions } from '@amtarc/auth-utils';

// Single permission
await definePermission({
  id: 'posts:create',
  name: 'Create Posts',
  description: 'Allows creating new blog posts',
  resourceType: 'post',
  actions: ['create']
});

// Multiple permissions
await definePermissions([
  {
    id: 'posts:read',
    name: 'Read Posts',
    resourceType: 'post',
    actions: ['read']
  },
  {
    id: 'posts:update',
    name: 'Update Posts',
    resourceType: 'post',
    actions: ['update']
  },
  {
    id: 'posts:delete',
    name: 'Delete Posts',
    resourceType: 'post',
    actions: ['delete']
  }
]);
```

### Define Roles

```typescript
import { defineRole, grantPermission } from '@amtarc/auth-utils';

// Create a role
const editorRole = await defineRole({
  id: 'editor',
  name: 'Editor',
  description: 'Can create and edit posts'
});

// Grant permissions to role
await grantPermissions('editor', [
  'posts:create',
  'posts:read',
  'posts:update'
]);

// Admin role with more permissions
await defineRole({
  id: 'admin',
  name: 'Administrator',
  description: 'Full access to all resources'
});

await grantPermissions('admin', [
  'posts:create',
  'posts:read',
  'posts:update',
  'posts:delete',
  'users:manage'
]);
```

### Assign Roles to Users

```typescript
import { assignRole } from '@amtarc/auth-utils';

// Assign role to user
await assignRole('user-123', 'editor');

// Assign with expiration
await assignRole('user-456', 'admin', {
  expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000 // 30 days
});

// Assign with scope (e.g., organization-specific)
await assignRole('user-789', 'editor', {
  scope: 'org:acme-corp'
});
```

## Permission Checks

### Basic Permission Check

```typescript
import { hasPermission, requirePermission } from '@amtarc/auth-utils';

// Check if user has permission (returns boolean)
const canDelete = await hasPermission('user-123', 'posts:delete');

if (canDelete) {
  // Allow deletion
}

// Require permission (throws if unauthorized)
await requirePermission('user-123', 'posts:delete');
// If we reach here, user is authorized
```

### Multiple Permission Checks

```typescript
import { hasAnyPermission, hasAllPermissions } from '@amtarc/auth-utils';

// Check if user has ANY of the permissions (OR logic)
const canModify = await hasAnyPermission('user-123', [
  'posts:update',
  'posts:delete'
]);

// Check if user has ALL permissions (AND logic)
const canPublish = await hasAllPermissions('user-123', [
  'posts:create',
  'posts:publish',
  'posts:feature'
]);
```

### Permission Check with Options

```typescript
import { hasPermission, PermissionCheckOptions } from '@amtarc/auth-utils';

const options: PermissionCheckOptions = {
  // Check within specific scope
  scope: 'org:acme-corp',
  
  // Include inherited permissions from parent roles
  includeInherited: true,
  
  // Require ALL or ANY permissions
  mode: 'AND' // or 'OR'
};

const hasAccess = await hasPermission('user-123', 'posts:delete', options);
```

## Role Checks

### Basic Role Check

```typescript
import { hasRole, requireRole } from '@amtarc/auth-utils';

// Check if user has role (returns boolean)
const isAdmin = await hasRole('user-123', 'admin');

if (isAdmin) {
  // Show admin features
}

// Require role (throws if user doesn't have it)
await requireRole('user-123', 'moderator');
```

### Multiple Role Checks

```typescript
import { hasAnyRole, hasAllRoles } from '@amtarc/auth-utils';

// Check if user has ANY role
const isStaff = await hasAnyRole('user-123', ['admin', 'moderator', 'editor']);

// Check if user has ALL roles
const isSuperUser = await hasAllRoles('user-123', ['admin', 'superuser']);
```

### Scoped Role Check

```typescript
import { hasRole } from '@amtarc/auth-utils';

// Check role within specific scope
const isOrgAdmin = await hasRole('user-123', 'admin', 'org:acme-corp');
```

## Role Hierarchy

Roles can inherit permissions from parent roles, creating a hierarchy.

### Defining Role Hierarchy

```typescript
import { defineRole, grantPermission } from '@amtarc/auth-utils';

// Base role
await defineRole({
  id: 'user',
  name: 'User',
  description: 'Basic user'
});

await grantPermissions('user', ['posts:read', 'profile:read']);

// Editor inherits from user
await defineRole({
  id: 'editor',
  name: 'Editor',
  description: 'Content editor',
  parents: ['user'] // Inherits user permissions
});

await grantPermissions('editor', ['posts:create', 'posts:update']);

// Admin inherits from editor (and transitively from user)
await defineRole({
  id: 'admin',
  name: 'Administrator',
  description: 'Full administrator',
  parents: ['editor'] // Inherits editor + user permissions
});

await grantPermissions('admin', ['posts:delete', 'users:manage']);
```

### How Inheritance Works

```typescript
import { hasPermission, getRolePermissions } from '@amtarc/auth-utils';

// User with 'admin' role has permissions from:
// - admin role directly
// - editor role (parent)
// - user role (grandparent)

await assignRole('user-123', 'admin');

// All of these return true:
await hasPermission('user-123', 'users:manage');  // From admin
await hasPermission('user-123', 'posts:update');  // From editor
await hasPermission('user-123', 'posts:read');    // From user

// Get all permissions for a role (including inherited)
const permissions = await getRolePermissions('admin', {
  includeInherited: true
});
// Returns: Set(['users:manage', 'posts:delete', 'posts:create', 
//                'posts:update', 'posts:read', 'profile:read'])
```

## Role & Permission Management

### Get Role Information

```typescript
import { getRole, listRoles } from '@amtarc/auth-utils';

// Get single role
const role = await getRole('editor');
console.log(role);
// {
//   id: 'editor',
//   name: 'Editor',
//   description: 'Content editor',
//   permissions: Set(['posts:create', 'posts:update']),
//   parents: Set(['user']),
//   createdAt: 1234567890,
//   updatedAt: 1234567890
// }

// List all roles
const roles = await listRoles();
```

### Update Roles

```typescript
import { updateRole, deleteRole } from '@amtarc/auth-utils';

// Update role properties
await updateRole('editor', {
  description: 'Updated description',
  metadata: { department: 'content' }
});

// Delete role
await deleteRole('obsolete-role');
```

### Get Permission Information

```typescript
import { getPermission, listPermissions } from '@amtarc/auth-utils';

// Get single permission
const permission = await getPermission('posts:delete');

// List all permissions
const permissions = await listPermissions();
```

### Update Permissions

```typescript
import { updatePermission, deletePermission } from '@amtarc/auth-utils';

// Update permission
await updatePermission('posts:delete', {
  description: 'Allows permanent deletion of posts',
  metadata: { dangerous: true }
});

// Delete permission
await deletePermission('deprecated:permission');
```

### Manage Role Permissions

```typescript
import { 
  grantPermission, 
  grantPermissions,
  revokePermission,
  getRolePermissions 
} from '@amtarc/auth-utils';

// Grant single permission
await grantPermission('editor', 'posts:publish');

// Grant multiple permissions
await grantPermissions('moderator', [
  'posts:approve',
  'comments:moderate',
  'users:warn'
]);

// Revoke permission
await revokePermission('editor', 'posts:delete');

// Get all permissions for role
const permissions = await getRolePermissions('editor');
```

### Manage User Roles

```typescript
import { getUserRoles, removeRole } from '@amtarc/auth-utils';

// Get all roles for user
const userRoles = await getUserRoles('user-123');
console.log(userRoles);
// [
//   {
//     userId: 'user-123',
//     roleId: 'editor',
//     assignedAt: 1234567890,
//     scope: 'org:acme'
//   }
// ]

// Remove role from user
await removeRole('user-123', 'editor');

// Remove scoped role
await removeRole('user-123', 'admin', 'org:acme');
```

## RBAC Guards

Guards provide declarative permission and role checking with automatic error handling.

### Using Guards with Managers

```typescript
import { RBACGuards, RoleManager, MemoryRBACStorage } from '@amtarc/auth-utils';

const storage = new MemoryRBACStorage();
const roleManager = new RoleManager({ storage });

const guards = new RBACGuards({
  roleManager,
  throwOnFailure: true // Throw errors instead of returning false
});

// Check permission (throws InsufficientPermissionError if unauthorized)
await guards.requirePermission(
  { userId: 'user-123' },
  'posts:delete'
);

// Check role (throws InsufficientRoleError if unauthorized)
await guards.requireRole(
  { userId: 'user-123' },
  'admin'
);
```

### Guard Options

```typescript
import { createRBACGuards } from '@amtarc/auth-utils';

const guards = createRBACGuards({
  roleManager,
  throwOnFailure: false, // Return false instead of throwing
  onError: (error, context) => {
    // Optional custom error handling
    console.log('Authorization failed:', error.message);
  }
});

// Non-throwing check
const hasAccess = await guards.hasPermission('user-123', 'posts:delete');
// Returns: true or false, never throws
```

## Error Handling

The RBAC module provides specialized error classes for authorization failures.

### Error Types

```typescript
import {
  InsufficientRoleError,
  InsufficientPermissionError,
  RoleNotFoundError,
  PermissionNotFoundError,
  RoleExistsError,
  PermissionExistsError
} from '@amtarc/auth-utils/authorization/types';

try {
  await requirePermission('user-123', 'posts:delete');
} catch (error) {
  if (error instanceof InsufficientPermissionError) {
    console.error('User lacks permission:', error.code); // 'INSUFFICIENT_PERMISSION'
    console.error('Details:', error.context);
  }
}
```

### Error Handling Patterns

```typescript
import { requireRole } from '@amtarc/auth-utils';
import { InsufficientRoleError } from '@amtarc/auth-utils/authorization/types';

async function deletePost(userId: string, postId: string) {
  try {
    // Check authorization
    await requireRole(userId, 'admin');
    
    // Proceed with deletion
    await db.posts.delete(postId);
    
  } catch (error) {
    if (error instanceof InsufficientRoleError) {
      return {
        success: false,
        error: 'Unauthorized: Admin role required',
        code: error.code
      };
    }
    throw error;
  }
}
```

### All Authorization Errors

| Error Class | Code | When Thrown |
|------------|------|-------------|
| `InsufficientRoleError` | `INSUFFICIENT_ROLE` | User lacks required role |
| `InsufficientPermissionError` | `INSUFFICIENT_PERMISSION` | User lacks required permission |
| `RoleNotFoundError` | `ROLE_NOT_FOUND` | Referenced role doesn't exist |
| `PermissionNotFoundError` | `PERMISSION_NOT_FOUND` | Referenced permission doesn't exist |
| `RoleExistsError` | `ROLE_EXISTS` | Attempting to create duplicate role |
| `PermissionExistsError` | `PERMISSION_EXISTS` | Attempting to create duplicate permission |
| `ResourceAccessDeniedError` | `RESOURCE_ACCESS_DENIED` | Access to resource denied |

## Advanced Usage

### Class-Based API

For advanced control, use manager classes directly:

```typescript
import { 
  PermissionManager, 
  RoleManager,
  MemoryRBACStorage 
} from '@amtarc/auth-utils';

const storage = new MemoryRBACStorage();

// Permission manager
const permissionManager = new PermissionManager({ storage });
await permissionManager.definePermission({
  id: 'posts:create',
  name: 'Create Posts'
});

// Role manager
const roleManager = new RoleManager({ storage });
await roleManager.defineRole({
  id: 'editor',
  name: 'Editor'
});

await roleManager.grantPermission('editor', 'posts:create');
await roleManager.assignRole('user-123', 'editor');
```

### Role Hierarchy Validation

```typescript
import { RoleHierarchy, MemoryRBACStorage } from '@amtarc/auth-utils';

const storage = new MemoryRBACStorage();
const hierarchy = new RoleHierarchy({ storage });

// Validate a specific role's hierarchy
const validation = await hierarchy.validateHierarchy('admin');

if (!validation.valid) {
  console.error('Hierarchy errors:', validation.errors);
  // ['Circular dependency detected in role hierarchy for admin']
}

// Validate entire role system
const fullValidation = await hierarchy.validateAll();

// Calculate role depth (distance from root)
const depth = await hierarchy.calculateDepth('admin');

// Get all ancestors
const ancestors = await hierarchy.getAncestors('admin');
// Returns: Set(['editor', 'user'])

// Get all descendants
const descendants = await hierarchy.getDescendants('user');
// Returns: Set(['editor', 'admin', 'moderator'])
```

### Custom Storage Adapter

Implement the `RBACStorageAdapter` interface for persistent storage:

```typescript
import { RBACStorageAdapter, Role, Permission, UserRole } from '@amtarc/auth-utils';

class PostgresRBACStorage implements RBACStorageAdapter {
  constructor(private db: Database) {}

  async getRole(roleId: string): Promise<Role | null> {
    const row = await this.db.query(
      'SELECT * FROM roles WHERE id = $1',
      [roleId]
    );
    return row ? this.deserializeRole(row) : null;
  }

  async saveRole(role: Role): Promise<void> {
    await this.db.query(
      'INSERT INTO roles (id, name, description, permissions, parents) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET name = $2, description = $3, permissions = $4, parents = $5',
      [
        role.id,
        role.name,
        role.description,
        Array.from(role.permissions),
        role.parents ? Array.from(role.parents) : null
      ]
    );
  }

  // Implement remaining methods...
  async deleteRole(roleId: string): Promise<void> { /* ... */ }
  async listRoles(): Promise<Role[]> { /* ... */ }
  async getPermission(permissionId: string): Promise<Permission | null> { /* ... */ }
  async savePermission(permission: Permission): Promise<void> { /* ... */ }
  async deletePermission(permissionId: string): Promise<void> { /* ... */ }
  async listPermissions(): Promise<Permission[]> { /* ... */ }
  async getUserRoles(userId: string): Promise<UserRole[]> { /* ... */ }
  async assignUserRole(assignment: UserRole): Promise<void> { /* ... */ }
  async removeUserRole(userId: string, roleId: string, scope?: string): Promise<void> { /* ... */ }
  async listUsersByRole(roleId: string): Promise<string[]> { /* ... */ }
}

// Use custom storage
const storage = new PostgresRBACStorage(db);
setDefaultRBACStorage(storage);
```

## Integration Examples

### Express Middleware

```typescript
import { hasPermission } from '@amtarc/auth-utils';
import { InsufficientPermissionError } from '@amtarc/auth-utils/authorization/types';

function requirePermission(permission: string) {
  return async (req, res, next) => {
    const userId = req.session?.userId;
    
    if (!userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
      const hasAccess = await hasPermission(userId, permission);
      
      if (!hasAccess) {
        return res.status(403).json({ 
          error: 'Insufficient permissions',
          required: permission
        });
      }
      
      next();
    } catch (error) {
      next(error);
    }
  };
}

// Use in routes
app.delete('/posts/:id', requirePermission('posts:delete'), async (req, res) => {
  // User is authorized
  await deletePost(req.params.id);
  res.json({ success: true });
});
```

### Combined with Session Validation

```typescript
import { validateSession } from '@amtarc/auth-utils';
import { hasPermission } from '@amtarc/auth-utils';

async function authorizedRequest(sessionId: string, permission: string) {
  // 1. Validate session
  const validation = await validateSession(sessionId, storage);
  
  if (!validation.valid) {
    throw new Error(`Session invalid: ${validation.reason}`);
  }
  
  const userId = validation.session.userId;
  
  // 2. Check permission
  const hasAccess = await hasPermission(userId, permission);
  
  if (!hasAccess) {
    throw new InsufficientPermissionError(permission, { userId });
  }
  
  // User is authenticated and authorized
  return validation.session;
}

// Usage
const session = await authorizedRequest(sessionId, 'posts:delete');
```

### Multi-Tenant RBAC

```typescript
import { assignRole, hasPermission } from '@amtarc/auth-utils';

// Assign tenant-scoped roles
await assignRole('user-123', 'admin', {
  scope: 'tenant:acme-corp'
});

await assignRole('user-123', 'editor', {
  scope: 'tenant:beta-inc'
});

// Check permissions within tenant scope
const canDeleteInAcme = await hasPermission(
  'user-123',
  'posts:delete',
  { scope: 'tenant:acme-corp' }
); // true (admin in acme-corp)

const canDeleteInBeta = await hasPermission(
  'user-123',
  'posts:delete',
  { scope: 'tenant:beta-inc' }
); // false (only editor in beta-inc)
```

### Time-Limited Access

```typescript
import { assignRole } from '@amtarc/auth-utils';

// Grant temporary admin access
const oneDayFromNow = Date.now() + 24 * 60 * 60 * 1000;

await assignRole('user-123', 'admin', {
  expiresAt: oneDayFromNow,
  metadata: {
    reason: 'Emergency maintenance',
    grantedBy: 'superuser-001'
  }
});

// Role assignment expires automatically after 24 hours
```

## TypeScript Support

All RBAC functions are fully typed:

```typescript
import type {
  Role,
  RoleId,
  Permission,
  PermissionId,
  UserRole,
  RoleOptions,
  PermissionCheckOptions,
  HierarchyValidation
} from '@amtarc/auth-utils';

// Type-safe role definition
const role: Role = {
  id: 'editor',
  name: 'Editor',
  description: 'Content editor',
  permissions: new Set(['posts:create', 'posts:update']),
  parents: new Set(['user']),
  createdAt: Date.now(),
  updatedAt: Date.now()
};

// Type-safe permission check options
const options: PermissionCheckOptions = {
  scope: 'tenant:acme',
  includeInherited: true,
  mode: 'AND'
};
```

## Best Practices

### 1. Permission Naming Convention

Use a consistent naming pattern:

```typescript
// Format: resource:action
'posts:create'
'posts:read'
'posts:update'
'posts:delete'

// For specific actions:
'posts:publish'
'posts:archive'
'users:ban'
'settings:manage'

// For admin actions:
'admin:users'
'admin:system'
```

### 2. Role Hierarchy Design

```typescript
// Keep hierarchy shallow (2-3 levels max)
// Root -> Manager -> Employee
//      -> Admin   -> Moderator

// Avoid deep hierarchies:
//  SuperAdmin -> Admin -> Manager -> Supervisor -> Employee
```

### 3. Prefer Functional API

```typescript
//  Recommended (functional)
await hasPermission('user-123', 'posts:delete');

//  Advanced use only (class-based)
const guards = new RBACGuards({ roleManager });
await guards.hasPermission('user-123', 'posts:delete');
```

### 4. Use Scopes for Multi-Tenancy

```typescript
// Organization-scoped roles
await assignRole(userId, 'admin', { scope: `org:${orgId}` });

// Team-scoped roles
await assignRole(userId, 'lead', { scope: `team:${teamId}` });

// Check with scope
await hasPermission(userId, 'projects:delete', {
  scope: `org:${orgId}`
});
```

### 5. Handle Errors Gracefully

```typescript
import { InsufficientPermissionError } from '@amtarc/auth-utils/authorization/types';

try {
  await requirePermission(userId, 'admin:users');
} catch (error) {
  if (error instanceof InsufficientPermissionError) {
    // Log for security audit
    logger.warn('Unauthorized access attempt', {
      userId,
      permission: 'admin:users',
      timestamp: Date.now()
    });
    
    // Return user-friendly message
    return { error: 'You do not have permission to perform this action' };
  }
  throw error;
}
```

## Performance Optimization

### Permission Caching

```typescript
// Cache permission checks for frequently accessed data
const cache = new Map<string, boolean>();

async function cachedHasPermission(
  userId: string,
  permission: string
): Promise<boolean> {
  const key = `${userId}:${permission}`;
  
  if (cache.has(key)) {
    return cache.get(key)!;
  }
  
  const result = await hasPermission(userId, permission);
  cache.set(key, result);
  
  // Clear cache after 5 minutes
  setTimeout(() => cache.delete(key), 5 * 60 * 1000);
  
  return result;
}
```

### Batch Operations

```typescript
// Instead of individual checks:
//  Inefficient
for (const permission of permissions) {
  await hasPermission(userId, permission);
}

//  Efficient - use batch function
await hasAllPermissions(userId, permissions);
```

## See Also

- [Guards & Middleware](/guide/guards) - Declarative auth guards
- [Error Handling](/guide/errors) - Error types and handling
- [Session Management](/guide/sessions) - User session management
- [API Reference](/api/core) - Complete API documentation
