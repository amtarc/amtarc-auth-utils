# Resource-Based Access Control

Manage fine-grained access to specific resources with ownership patterns and permission scopes.

## Overview

Resource-based access control provides:

- **Resource Manager**: CRUD operations with permission management
- **Ownership Patterns**: Pre-built patterns for common scenarios (owner, team, organization)
- **Permission Scopes**: Four scope levels (own, team, organization, all)
- **Resource Actions**: Nine standard actions (create, read, update, delete, admin, share, comment, download, execute)
- **Expiring Permissions**: Time-limited access grants
- **Transfer Ownership**: Audit-trailed ownership transfers
- **Storage Adapters**: Pluggable storage (Memory included)

## Quick Start

### Installation

```bash
npm install @amtarc/auth-utils
```

### Setup Resource Manager

```typescript
import { 
  ResourceManager, 
  MemoryResourceStorage 
} from '@amtarc/auth-utils/authorization/resource';

const storage = new MemoryResourceStorage();
const resourceManager = new ResourceManager({ storage });
```

### Create a Resource

```typescript
import { ResourceActions } from '@amtarc/auth-utils/authorization/resource';

const document = await resourceManager.createResource({
  id: 'doc-123',
  type: 'document',
  ownerId: 'user-456',
  metadata: {
    title: 'Q4 Financial Report',
    department: 'finance',
    classification: 'confidential'
  }
});
```

### Grant Access

```typescript
// Grant read and update access
await resourceManager.grantAccess(
  'user-789',              // userId
  'doc-123',               // resourceId
  'document',              // resourceType
  [ResourceActions.READ, ResourceActions.UPDATE],
  {
    scope: 'own',          // Permission scope
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    grantedBy: 'user-456',
    metadata: { 
      reason: 'Project collaboration',
      ticketId: 'PROJ-123'
    }
  }
);
```

### Check Access

```typescript
// Check if user can access resource
const canUpdate = await resourceManager.canAccess(
  'user-789',
  'doc-123',
  ResourceActions.UPDATE
);

if (canUpdate) {
  // User has update permission
  console.log('Access granted!');
} else {
  console.log('Access denied');
}
```

## Resource Actions

Nine built-in actions for common operations:

```typescript
import { ResourceActions } from '@amtarc/auth-utils/authorization/resource';

// Basic CRUD
ResourceActions.CREATE   // 'create' - Create new resources
ResourceActions.READ     // 'read' - View/read resources
ResourceActions.UPDATE   // 'update' - Modify resources
ResourceActions.DELETE   // 'delete' - Remove resources

// Advanced actions
ResourceActions.ADMIN    // 'admin' - Full administrative access
ResourceActions.SHARE    // 'share' - Share with others
ResourceActions.COMMENT  // 'comment' - Add comments/feedback
ResourceActions.DOWNLOAD // 'download' - Download resource
ResourceActions.EXECUTE  // 'execute' - Run/execute resource
```

### Using Actions

```typescript
// Grant multiple actions at once
await resourceManager.grantAccess(
  userId,
  resourceId,
  'file',
  [
    ResourceActions.READ,
    ResourceActions.DOWNLOAD,
    ResourceActions.COMMENT
  ]
);

// Check specific action
const canDelete = await resourceManager.canAccess(
  userId,
  resourceId,
  ResourceActions.DELETE
);
```

## Permission Scopes

Control visibility and inheritance of permissions:

### Scope Types

```typescript
type PermissionScope = 'own' | 'team' | 'organization' | 'all';
```

#### Own Scope

User can only access their own resources:

```typescript
await resourceManager.grantAccess(
  userId,
  resourceId,
  'document',
  ResourceActions.READ,
  { scope: 'own' }
);
```

#### Team Scope

User can access team resources:

```typescript
await resourceManager.grantAccess(
  userId,
  resourceId,
  'project',
  [ResourceActions.READ, ResourceActions.UPDATE],
  { scope: 'team' }
);
```

#### Organization Scope

User can access organization-wide resources:

```typescript
await resourceManager.grantAccess(
  userId,
  resourceId,
  'report',
  ResourceActions.READ,
  { scope: 'organization' }
);
```

#### All Scope

User can access all resources (admin-level):

```typescript
await resourceManager.grantAccess(
  userId,
  resourceId,
  'system',
  ResourceActions.ADMIN,
  { scope: 'all' }
);
```

## Ownership Patterns

Pre-built patterns for common ownership scenarios.

### Full Owner Access

Owner has complete control:

```typescript
import { OwnershipPatterns } from '@amtarc/auth-utils/authorization/resource';

const ownerRule = OwnershipPatterns.createFullOwnerAccess('document');

// Check ownership
await resourceManager.checkOwnership(userId, resourceId, ownerRule);
// Throws ResourceAccessDeniedError if user.id !== resource.ownerId
```

### Read-Write Owner

Owner can read and modify, but not delete:

```typescript
const readWriteRule = OwnershipPatterns.createReadWriteOwner('document');
// Grants: [READ, UPDATE, SHARE, COMMENT]

await resourceManager.checkOwnership(userId, resourceId, readWriteRule);
```

### Read-Only Owner

Owner can only view:

```typescript
const readOnlyRule = OwnershipPatterns.createReadOnlyOwner('document');
// Grants: [READ, DOWNLOAD]

await resourceManager.checkOwnership(userId, resourceId, readOnlyRule);
```

### Team-Based Access

Access based on team membership:

```typescript
const teamRule = OwnershipPatterns.createTeamBasedAccess('project');

// Validates: user.teamId === resource.teamId
await resourceManager.checkOwnership(userId, resourceId, teamRule);
```

### Organization-Based Access

Access based on organization:

```typescript
const orgRule = OwnershipPatterns.createOrganizationAccess('report');

// Validates: user.organizationId === resource.organizationId
await resourceManager.checkOwnership(userId, resourceId, orgRule);
```

### Custom Ownership Rules

Create domain-specific ownership logic:

```typescript
import { createCustomOwnershipRule } from '@amtarc/auth-utils/authorization/resource';

const departmentOwnerRule = createCustomOwnershipRule(
  'department-admin',
  'document',
  async ({ userId, resource, action }) => {
    // Fetch user and check department
    const user = await db.users.findById(userId);
    const doc = resource as Document;
    
    // Check if user is admin of document's department
    if (user.role !== 'admin') return false;
    if (user.department !== doc.metadata.department) return false;
    
    return true;
  },
  [ResourceActions.READ, ResourceActions.UPDATE, ResourceActions.DELETE]
);

// Use custom rule
await resourceManager.checkOwnership(userId, resourceId, departmentOwnerRule);
```

## Resource Management

### List User Resources

Get all resources accessible by a user:

```typescript
const resources = await resourceManager.listUserResources('user-123', {
  resourceType: 'document', // Optional: filter by type
  includeOwned: true        // Include resources user owns
});

console.log(resources);
// [
//   { id: 'doc-1', type: 'document', ownerId: 'user-123', ... },
//   { id: 'doc-2', type: 'document', ownerId: 'user-456', ... }
// ]
```

### List Resource Users

Get all users with access to a resource:

```typescript
const users = await resourceManager.listResourceUsers('doc-123', {
  action: ResourceActions.UPDATE // Optional: filter by action
});

console.log(users);
// ['user-456', 'user-789', 'user-101']
```

### Transfer Ownership

Transfer resource to another user:

```typescript
await resourceManager.transferOwnership(
  'doc-123',              // resourceId
  'new-owner-456',        // newOwnerId
  'admin-789'             // transferredBy (for audit trail)
);

// Previous owner loses ownership
// New owner gains full control
// Transfer is logged in metadata
```

### Revoke Access

Remove user's access to a resource:

```typescript
await resourceManager.revokeAccess('user-123', 'doc-456');

// Removes all permissions for this user-resource pair
```

### Delete Resource

Remove resource and all associated permissions:

```typescript
await resourceManager.deleteResource('doc-123');

// Deletes resource and automatically removes all permissions
```

## Time-Limited Access

Grant temporary access with expiration:

```typescript
// Grant 24-hour download access
const expiresAt = Date.now() + 24 * 60 * 60 * 1000;

await resourceManager.grantAccess(
  'external-contractor-123',
  'confidential-doc-456',
  'document',
  ResourceActions.DOWNLOAD,
  {
    expiresAt,
    grantedBy: 'admin-789',
    metadata: {
      reason: 'External audit',
      requestId: 'AUDIT-2024-001',
      approver: 'compliance-officer'
    }
  }
);

// Access automatically expires after 24 hours
// Expired permissions are automatically filtered out during checks
```

## Real-World Examples

### Document Collaboration

```typescript
// Owner creates document
const doc = await resourceManager.createResource({
  id: 'report-q4-2024',
  type: 'document',
  ownerId: 'manager-123',
  metadata: {
    title: 'Q4 2024 Financial Report',
    department: 'finance',
    status: 'draft'
  }
});

// Grant collaborator access
await resourceManager.grantAccess(
  'analyst-456',
  'report-q4-2024',
  'document',
  [ResourceActions.READ, ResourceActions.UPDATE, ResourceActions.COMMENT],
  {
    scope: 'team',
    grantedBy: 'manager-123',
    metadata: { role: 'contributor' }
  }
);

// Grant reviewer read-only access
await resourceManager.grantAccess(
  'reviewer-789',
  'report-q4-2024',
  'document',
  [ResourceActions.READ, ResourceActions.COMMENT],
  {
    scope: 'organization',
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
    grantedBy: 'manager-123',
    metadata: { role: 'reviewer' }
  }
);
```

### File Sharing

```typescript
// Create shared folder
const folder = await resourceManager.createResource({
  id: 'team-resources',
  type: 'folder',
  ownerId: 'team-lead-123',
  metadata: {
    name: 'Team Resources',
    path: '/shared/team-resources'
  }
});

// Grant team members access
const teamMembers = ['dev-456', 'dev-789', 'designer-101'];

for (const memberId of teamMembers) {
  await resourceManager.grantAccess(
    memberId,
    'team-resources',
    'folder',
    [ResourceActions.READ, ResourceActions.DOWNLOAD, ResourceActions.SHARE],
    {
      scope: 'team',
      grantedBy: 'team-lead-123'
    }
  );
}
```

### Project Access Control

```typescript
// Create project
const project = await resourceManager.createResource({
  id: 'project-apollo',
  type: 'project',
  ownerId: 'pm-123',
  metadata: {
    name: 'Project Apollo',
    department: 'engineering',
    budget: 500000
  }
});

// Grant PM full access
await resourceManager.grantAccess(
  'pm-123',
  'project-apollo',
  'project',
  [
    ResourceActions.READ,
    ResourceActions.UPDATE,
    ResourceActions.DELETE,
    ResourceActions.ADMIN,
    ResourceActions.SHARE
  ],
  { scope: 'all' }
);

// Grant developers read/update
await resourceManager.grantAccess(
  'dev-team',
  'project-apollo',
  'project',
  [ResourceActions.READ, ResourceActions.UPDATE],
  { scope: 'team' }
);

// Grant stakeholders read-only
await resourceManager.grantAccess(
  'stakeholder-group',
  'project-apollo',
  'project',
  ResourceActions.READ,
  { scope: 'organization' }
);
```

### Hierarchical Resources

Inherit permissions from parent resources:

```typescript
// Create folder
const folder = await resourceManager.createResource({
  id: 'folder-projects',
  type: 'folder',
  ownerId: 'team-lead-123',
  metadata: { path: '/projects', name: 'Projects' }
});

// Grant folder access
await resourceManager.grantAccess(
  'developer-456',
  'folder-projects',
  'folder',
  [ResourceActions.READ, ResourceActions.UPDATE]
);

// Create file in folder (inherits permissions)
const file = await resourceManager.createResource({
  id: 'file-readme',
  type: 'file',
  ownerId: 'team-lead-123',
  metadata: {
    path: '/projects/readme.md',
    parentId: 'folder-projects'
  }
});

// Check inherited access
const canAccessFile = await resourceManager.canAccess(
  'developer-456',
  'file-readme',
  ResourceActions.READ
);
// Returns true (inherited from parent folder)
```

## Integration with Express

```typescript
import { 
  ResourceManager, 
  ResourceActions 
} from '@amtarc/auth-utils/authorization/resource';
import type { Request, Response, NextFunction } from 'express';

// Middleware factory
function requireResourceAccess(action: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const userId = req.user?.id;
    const resourceId = req.params.id;

    if (!userId) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
      const hasAccess = await resourceManager.canAccess(
        userId,
        resourceId,
        action
      );

      if (!hasAccess) {
        return res.status(403).json({
          error: 'Access denied',
          resource: resourceId,
          action
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

// Use in routes
app.get(
  '/documents/:id',
  requireResourceAccess(ResourceActions.READ),
  async (req, res) => {
    const document = await getDocument(req.params.id);
    res.json(document);
  }
);

app.put(
  '/documents/:id',
  requireResourceAccess(ResourceActions.UPDATE),
  async (req, res) => {
    const document = await updateDocument(req.params.id, req.body);
    res.json(document);
  }
);

app.delete(
  '/documents/:id',
  requireResourceAccess(ResourceActions.DELETE),
  async (req, res) => {
    await deleteDocument(req.params.id);
    res.json({ success: true });
  }
);

// Share resource
app.post(
  '/documents/:id/share',
  requireResourceAccess(ResourceActions.SHARE),
  async (req, res) => {
    await resourceManager.grantAccess(
      req.body.userId,
      req.params.id,
      'document',
      req.body.actions,
      {
        grantedBy: req.user.id,
        expiresAt: req.body.expiresAt,
        metadata: { sharedVia: 'api' }
      }
    );
    res.json({ success: true });
  }
);
```

## Storage Adapters

### Memory Storage (Built-in)

```typescript
import { MemoryResourceStorage } from '@amtarc/auth-utils/authorization/resource';

const storage = new MemoryResourceStorage();
const manager = new ResourceManager({ storage });

// All data stored in memory (for development/testing)
```

### Custom Storage Adapter

Implement for persistent storage:

```typescript
import type { 
  ResourceStorageAdapter,
  Resource,
  ResourcePermission
} from '@amtarc/auth-utils/authorization/resource';

class PostgresResourceStorage implements ResourceStorageAdapter {
  constructor(private db: Database) {}

  async getResource(id: string): Promise<Resource | null> {
    const row = await this.db.query(
      'SELECT * FROM resources WHERE id = $1',
      [id]
    );
    return row ? this.deserializeResource(row) : null;
  }

  async saveResource(resource: Resource): Promise<void> {
    await this.db.query(
      `INSERT INTO resources (id, type, owner_id, metadata)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET
         type = $2, owner_id = $3, metadata = $4`,
      [resource.id, resource.type, resource.ownerId, JSON.stringify(resource.metadata)]
    );
  }

  async deleteResource(id: string): Promise<void> {
    await this.db.query('DELETE FROM resources WHERE id = $1', [id]);
  }

  async saveResourcePermission(permission: ResourcePermission): Promise<void> {
    await this.db.query(
      `INSERT INTO resource_permissions 
       (user_id, resource_id, resource_type, actions, scope, granted_at, expires_at, granted_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (user_id, resource_id) DO UPDATE SET
         actions = $4, scope = $5, expires_at = $7`,
      [
        permission.userId,
        permission.resourceId,
        permission.resourceType,
        Array.from(permission.actions),
        permission.scope,
        permission.grantedAt,
        permission.expiresAt,
        permission.grantedBy
      ]
    );
  }

  async getResourcePermissions(resourceId: string): Promise<ResourcePermission[]> {
    const rows = await this.db.query(
      'SELECT * FROM resource_permissions WHERE resource_id = $1',
      [resourceId]
    );
    return rows.map(r => this.deserializePermission(r));
  }

  async getUserPermissions(userId: string): Promise<ResourcePermission[]> {
    const rows = await this.db.query(
      'SELECT * FROM resource_permissions WHERE user_id = $1',
      [userId]
    );
    return rows.map(r => this.deserializePermission(r));
  }

  async deleteResourcePermission(userId: string, resourceId: string): Promise<void> {
    await this.db.query(
      'DELETE FROM resource_permissions WHERE user_id = $1 AND resource_id = $2',
      [userId, resourceId]
    );
  }

  async listResources(filters?: { 
    type?: string; 
    ownerId?: string 
  }): Promise<Resource[]> {
    const conditions = [];
    const params = [];
    
    if (filters?.type) {
      conditions.push(`type = $${params.length + 1}`);
      params.push(filters.type);
    }
    if (filters?.ownerId) {
      conditions.push(`owner_id = $${params.length + 1}`);
      params.push(filters.ownerId);
    }
    
    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';
    const rows = await this.db.query(`SELECT * FROM resources ${where}`, params);
    
    return rows.map(r => this.deserializeResource(r));
  }
}

// Use custom storage
const storage = new PostgresResourceStorage(db);
const manager = new ResourceManager({ storage });
```

## TypeScript Support

All resource types are fully typed:

```typescript
import type {
  Resource,
  ResourceId,
  ResourcePermission,
  ResourceAction,
  OwnershipRule,
  PermissionScope,
  ResourceStorageAdapter
} from '@amtarc/auth-utils/authorization/resource';

// Type-safe resource
const resource: Resource = {
  id: 'doc-123',
  type: 'document',
  ownerId: 'user-456',
  metadata: {
    title: 'My Document',
    createdAt: Date.now()
  }
};

// Type-safe permission
const permission: ResourcePermission = {
  userId: 'user-789',
  resourceId: 'doc-123',
  resourceType: 'document',
  actions: new Set(['read', 'update']),
  scope: 'team',
  grantedAt: Date.now()
};

// Type-safe ownership rule
const rule: OwnershipRule = {
  id: 'owner-rule',
  resourceType: 'document',
  type: 'owner',
  defaultActions: ['read', 'update', 'delete'],
  validator: async ({ userId, resource }) => {
    return userId === resource.ownerId;
  }
};
```

## Best Practices

### 1. Define Clear Resource Types

Use consistent resource type naming:

```typescript
// ✅ Good
'document', 'file', 'project', 'folder'

// ❌ Avoid
'doc', 'Document', 'DOCUMENT'
```

### 2. Use Appropriate Scopes

Choose the right scope for each permission:

```typescript
// Own - Personal resources
scope: 'own'

// Team - Collaborative resources
scope: 'team'

// Organization - Shared resources
scope: 'organization'

// All - Admin/system resources
scope: 'all'
```

### 3. Implement Expiring Permissions

Always set expiration for temporary access:

```typescript
// External access should expire
await resourceManager.grantAccess(
  externalUserId,
  resourceId,
  type,
  actions,
  {
    expiresAt: Date.now() + 24 * 60 * 60 * 1000,
    metadata: { reason: 'Temporary collaboration' }
  }
);
```

### 4. Track Access Grants

Always include `grantedBy` for audit trails:

```typescript
await resourceManager.grantAccess(
  userId,
  resourceId,
  type,
  actions,
  {
    grantedBy: currentUserId,
    metadata: {
      reason: 'Project collaboration',
      ticketId: 'PROJ-123'
    }
  }
);
```

### 5. Clean Up on Resource Deletion

Always delete associated permissions when removing resources:

```typescript
// ✅ Good - deleteResource handles cleanup
await resourceManager.deleteResource(resourceId);

// ❌ Avoid - manual deletion leaves orphaned permissions
await storage.deleteResource(resourceId);
// Permissions still exist!
```

## Error Handling

Resource access errors:

```typescript
import { ResourceAccessDeniedError } from '@amtarc/auth-utils/authorization/types';

try {
  await resourceManager.checkOwnership(userId, resourceId, ownerRule);
} catch (error) {
  if (error instanceof ResourceAccessDeniedError) {
    console.error('Access denied:', error.context);
    // {
    //   userId: 'user-123',
    //   resourceId: 'doc-456',
    //   action: 'delete'
    // }
  }
}
```

## See Also

- [RBAC](/guide/authorization) - Role-Based Access Control
- [ABAC](/guide/abac) - Attribute-Based Access Control
- [Authorization Guards](/guide/authorization-guards) - Unified authorization guards
- [API Reference](/api/core) - Complete API documentation
