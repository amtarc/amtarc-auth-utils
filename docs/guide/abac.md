# Attribute-Based Access Control (ABAC)

Fine-grained access control based on attributes of users, resources, and environment.

## Overview

ABAC provides policy-based authorization with:

- **Policy Engine**: Evaluate complex access rules with caching
- **13 Comparison Operators**: Flexible attribute matching (eq, neq, gt, gte, lt, lte, in, notIn, contains, notContains, startsWith, endsWith, matches)
- **Logical Operators**: AND, OR, NOT for composing rules
- **Attribute Providers**: User, resource, environment, and custom attributes
- **Combining Algorithms**: deny-overrides, allow-overrides, first-applicable
- **Policy Storage**: Memory storage with versioning and filtering
- **Policy Caching**: Configurable TTL for performance optimization

## Quick Start

### Installation

```bash
npm install @amtarc/auth-utils
```

### Setup Policy Engine

```typescript
import { 
  MemoryPolicyStorage, 
  PolicyEngine 
} from '@amtarc/auth-utils/authorization/abac';

// Initialize storage
const storage = new MemoryPolicyStorage();

// Create policy engine
const policyEngine = new PolicyEngine({ 
  storage,
  cacheTTL: 5 * 60 * 1000 // 5 minutes (default)
});
```

### Define Your First Policy

```typescript
import type { Policy } from '@amtarc/auth-utils/authorization/abac';

const policy: Policy = {
  id: 'allow-owner-delete',
  name: 'Allow Resource Owner to Delete',
  effect: 'allow',
  rules: [
    {
      attribute: 'user.id',
      operator: 'eq',
      value: '${resource.ownerId}'
    }
  ],
  resourceType: 'document',
  action: 'delete'
};

await storage.savePolicy(policy);
```

### Evaluate Policy

```typescript
import type { PolicyContext } from '@amtarc/auth-utils/authorization/abac';

const context: PolicyContext = {
  user: { 
    id: 'user-123', 
    role: 'editor',
    department: 'engineering'
  },
  resource: { 
    id: 'doc-456', 
    ownerId: 'user-123', 
    type: 'document' 
  },
  action: 'delete'
};

const result = await policyEngine.evaluatePolicy('allow-owner-delete', context);

if (result.decision === 'allow') {
  // User can delete the document
  console.log('Access granted!');
} else {
  console.log('Access denied:', result.reason);
}
```

## Comparison Operators

ABAC supports 13 powerful operators for flexible attribute matching:

### Equality Operators

#### eq (Equal)

Check if values are equal:

```typescript
{
  attribute: 'user.role',
  operator: 'eq',
  value: 'admin'
}
```

#### neq (Not Equal)

Check if values are different:

```typescript
{
  attribute: 'resource.status',
  operator: 'neq',
  value: 'deleted'
}
```

### Numeric Operators

#### gt (Greater Than)

```typescript
{
  attribute: 'user.age',
  operator: 'gt',
  value: 18
}
```

#### gte (Greater Than or Equal)

```typescript
{
  attribute: 'resource.version',
  operator: 'gte',
  value: 2
}
```

#### lt (Less Than)

```typescript
{
  attribute: 'request.fileSize',
  operator: 'lt',
  value: 10485760 // 10MB
}
```

#### lte (Less Than or Equal)

```typescript
{
  attribute: 'user.loginAttempts',
  operator: 'lte',
  value: 3
}
```

### Array Membership Operators

#### in (Value in Array)

Check if value exists in an array:

```typescript
{
  attribute: 'user.role',
  operator: 'in',
  value: ['admin', 'moderator', 'superuser']
}
```

#### notIn (Value Not in Array)

Check if value doesn't exist in an array:

```typescript
{
  attribute: 'resource.status',
  operator: 'notIn',
  value: ['deleted', 'archived', 'suspended']
}
```

### String/Array Contains Operators

#### contains (Array/String Contains)

Check if array contains value or string contains substring:

```typescript
// Array contains
{
  attribute: 'user.permissions',
  operator: 'contains',
  value: 'documents:delete'
}

// String contains
{
  attribute: 'resource.tags',
  operator: 'contains',
  value: 'confidential'
}
```

#### notContains (Does Not Contain)

```typescript
{
  attribute: 'user.restrictions',
  operator: 'notContains',
  value: 'suspended'
}
```

### String Pattern Operators

#### startsWith (String Starts With)

```typescript
{
  attribute: 'resource.path',
  operator: 'startsWith',
  value: '/public/'
}
```

#### endsWith (String Ends With)

```typescript
{
  attribute: 'file.name',
  operator: 'endsWith',
  value: '.pdf'
}
```

#### matches (Regex Match)

```typescript
{
  attribute: 'user.email',
  operator: 'matches',
  value: '^[a-z]+@company\\.com$'
}
```

## Combining Rules with Logical Operators

### AND Logic

All rules must pass:

```typescript
const policy: Policy = {
  id: 'allow-senior-editor-publish',
  name: 'Allow Senior Editors to Publish',
  effect: 'allow',
  rules: [
    {
      operator: 'AND',
      rules: [
        {
          attribute: 'user.role',
          operator: 'eq',
          value: 'editor'
        },
        {
          attribute: 'user.seniority',
          operator: 'gte',
          value: 3
        },
        {
          attribute: 'resource.status',
          operator: 'eq',
          value: 'reviewed'
        }
      ]
    }
  ],
  resourceType: 'article',
  action: 'publish'
};
```

### OR Logic

Any rule can pass:

```typescript
const policy: Policy = {
  id: 'allow-owner-or-admin',
  name: 'Allow Owner or Admin',
  effect: 'allow',
  rules: [
    {
      operator: 'OR',
      rules: [
        {
          attribute: 'user.id',
          operator: 'eq',
          value: '${resource.ownerId}'
        },
        {
          attribute: 'user.role',
          operator: 'eq',
          value: 'admin'
        }
      ]
    }
  ],
  resourceType: 'document',
  action: 'delete'
};
```

### NOT Logic

Negation of a rule:

```typescript
const policy: Policy = {
  id: 'deny-guest-write',
  name: 'Deny Guest Write Access',
  effect: 'deny',
  rules: [
    {
      operator: 'NOT',
      rules: [
        {
          attribute: 'user.authenticated',
          operator: 'eq',
          value: true
        }
      ]
    }
  ],
  action: 'write'
};
```

### Nested Rule Groups

Combine multiple logical operators:

```typescript
const policy: Policy = {
  id: 'complex-access',
  name: 'Complex Access Rule',
  effect: 'allow',
  rules: [
    {
      operator: 'AND',
      rules: [
        {
          // User must be authenticated
          attribute: 'user.authenticated',
          operator: 'eq',
          value: true
        },
        {
          // AND (owner OR has admin permission)
          operator: 'OR',
          rules: [
            {
              attribute: 'user.id',
              operator: 'eq',
              value: '${resource.ownerId}'
            },
            {
              attribute: 'user.permissions',
              operator: 'contains',
              value: 'documents:admin'
            }
          ]
        },
        {
          // AND NOT suspended
          operator: 'NOT',
          rules: [
            {
              attribute: 'user.status',
              operator: 'eq',
              value: 'suspended'
            }
          ]
        }
      ]
    }
  ],
  resourceType: 'document',
  action: 'update'
};
```

## Attribute Providers

Attribute providers supply context data for policy evaluation.

### Built-in Providers

```typescript
import {
  UserAttributeProvider,
  ResourceAttributeProvider,
  EnvironmentAttributeProvider,
  CustomAttributeProvider
} from '@amtarc/auth-utils/authorization/abac';

// Register providers
policyEngine.registerProvider('user', new UserAttributeProvider());
policyEngine.registerProvider('resource', new ResourceAttributeProvider());
policyEngine.registerProvider('environment', new EnvironmentAttributeProvider());
```

### User Attribute Provider

Provides user information:

```typescript
// Available attributes:
// - user.id
// - user.role
// - user.department
// - user.permissions (array)
// - user.metadata.* (custom fields)

const policy: Policy = {
  id: 'department-access',
  effect: 'allow',
  rules: [
    {
      attribute: 'user.department',
      operator: 'eq',
      value: 'engineering'
    }
  ],
  action: 'access-internal-tools'
};
```

### Resource Attribute Provider

Provides resource information:

```typescript
// Available attributes:
// - resource.id
// - resource.type
// - resource.ownerId
// - resource.status
// - resource.createdAt
// - resource.metadata.* (custom fields)

const policy: Policy = {
  id: 'published-content-only',
  effect: 'allow',
  rules: [
    {
      attribute: 'resource.status',
      operator: 'eq',
      value: 'published'
    }
  ],
  resourceType: 'article',
  action: 'read'
};
```

### Environment Attribute Provider

Provides contextual information:

```typescript
// Available attributes:
// - environment.currentTime (timestamp)
// - environment.dayOfWeek ('monday', 'tuesday', etc.)
// - environment.hour (0-23)
// - environment.ipAddress
// - environment.userAgent

const policy: Policy = {
  id: 'business-hours-only',
  effect: 'allow',
  rules: [
    {
      operator: 'AND',
      rules: [
        {
          attribute: 'environment.hour',
          operator: 'gte',
          value: 9
        },
        {
          attribute: 'environment.hour',
          operator: 'lt',
          value: 17
        },
        {
          attribute: 'environment.dayOfWeek',
          operator: 'in',
          value: ['monday', 'tuesday', 'wednesday', 'thursday', 'friday']
        }
      ]
    }
  ],
  action: 'access-sensitive-data'
};
```

### Custom Attribute Provider

Create domain-specific attribute providers:

```typescript
import { 
  AttributeProvider, 
  AttributeValue, 
  PolicyContext 
} from '@amtarc/auth-utils/authorization/abac';

class OrganizationAttributeProvider implements AttributeProvider {
  async getAttribute(
    attributePath: string,
    context: PolicyContext
  ): Promise<AttributeValue> {
    const orgId = context.user?.organizationId;
    if (!orgId) return null;

    // Fetch from database
    const org = await db.organizations.findById(orgId);
    
    if (attributePath === 'organization.plan') {
      return org?.plan || null;
    }
    if (attributePath === 'organization.memberCount') {
      return org?.memberCount || 0;
    }
    if (attributePath === 'organization.features') {
      return org?.features || [];
    }
    
    return null;
  }
}

// Register custom provider
policyEngine.registerProvider('organization', new OrganizationAttributeProvider());

// Use in policies
const policy: Policy = {
  id: 'premium-feature',
  name: 'Premium Feature Access',
  effect: 'allow',
  rules: [
    {
      attribute: 'organization.plan',
      operator: 'in',
      value: ['premium', 'enterprise']
    }
  ],
  action: 'use-advanced-analytics'
};
```

## Policy Combining Algorithms

Control how multiple policies are combined when evaluating access.

### Deny Overrides (Default)

Any deny decision overrides allow decisions (most secure):

```typescript
const result = await policyEngine.evaluatePolicies(
  context,
  { combiningAlgorithm: 'deny-overrides' }
);

// If any policy denies, final decision is 'deny'
// Useful for: Security-first scenarios
```

### Allow Overrides

Any allow decision overrides deny decisions:

```typescript
const result = await policyEngine.evaluatePolicies(
  context,
  { combiningAlgorithm: 'allow-overrides' }
);

// If any policy allows, final decision is 'allow'
// Useful for: Flexibility-first scenarios
```

### First Applicable

Use the first matching policy's decision:

```typescript
const result = await policyEngine.evaluatePolicies(
  context,
  { combiningAlgorithm: 'first-applicable' }
);

// Returns decision from first applicable policy
// Useful for: Ordered policy evaluation
```

## Policy Storage

### Memory Storage

Built-in memory storage with filtering and versioning:

```typescript
import { MemoryPolicyStorage } from '@amtarc/auth-utils/authorization/abac';

const storage = new MemoryPolicyStorage();

// Save policy
await storage.savePolicy({
  id: 'policy-1',
  name: 'My Policy',
  effect: 'allow',
  rules: [/* ... */]
});

// Get policy
const policy = await storage.getPolicy('policy-1');

// List policies with filters
const allowPolicies = await storage.listPolicies({
  effect: 'allow'
});

const documentPolicies = await storage.listPolicies({
  resourceType: 'document',
  action: 'delete'
});

// Delete policy
await storage.deletePolicy('policy-1');
```

### Policy Versioning

Policies are automatically versioned:

```typescript
// Save policy (version 1)
await storage.savePolicy({ 
  id: 'policy-1', 
  name: 'First Version',
  effect: 'allow',
  rules: [/* ... */]
});

// Update policy (version increments)
await storage.savePolicy({ 
  id: 'policy-1', 
  name: 'Updated Version',
  effect: 'allow',
  rules: [/* updated rules */]
});

const policy = await storage.getPolicy('policy-1');
console.log(policy.metadata?.version); // 2
console.log(policy.metadata?.updatedAt); // timestamp
```

### Custom Storage Adapter

Implement `PolicyStorageAdapter` for persistent storage:

```typescript
import type { PolicyStorageAdapter, Policy } from '@amtarc/auth-utils/authorization/abac';

class PostgresPolicyStorage implements PolicyStorageAdapter {
  constructor(private db: Database) {}

  async getPolicy(id: string): Promise<Policy | null> {
    const row = await this.db.query(
      'SELECT * FROM policies WHERE id = $1',
      [id]
    );
    return row ? this.deserializePolicy(row) : null;
  }

  async savePolicy(policy: Policy): Promise<void> {
    await this.db.query(
      `INSERT INTO policies (id, name, effect, rules, resource_type, action, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (id) DO UPDATE SET
         name = $2, effect = $3, rules = $4, 
         resource_type = $5, action = $6, metadata = $7`,
      [
        policy.id,
        policy.name,
        policy.effect,
        JSON.stringify(policy.rules),
        policy.resourceType,
        policy.action,
        JSON.stringify(policy.metadata)
      ]
    );
  }

  async deletePolicy(id: string): Promise<void> {
    await this.db.query('DELETE FROM policies WHERE id = $1', [id]);
  }

  async listPolicies(filters?: {
    effect?: 'allow' | 'deny';
    resourceType?: string;
    action?: string;
  }): Promise<Policy[]> {
    // Implement filtered query
    const conditions = [];
    const params = [];
    
    if (filters?.effect) {
      conditions.push(`effect = $${params.length + 1}`);
      params.push(filters.effect);
    }
    // ... more conditions
    
    const where = conditions.length 
      ? `WHERE ${conditions.join(' AND ')}` 
      : '';
    
    const rows = await this.db.query(
      `SELECT * FROM policies ${where}`,
      params
    );
    
    return rows.map(r => this.deserializePolicy(r));
  }
}

// Use custom storage
const storage = new PostgresPolicyStorage(db);
const policyEngine = new PolicyEngine({ storage });
```

## Policy Caching

The policy engine caches evaluation results for performance:

```typescript
// Configure cache TTL (default: 5 minutes)
const policyEngine = new PolicyEngine({
  storage,
  cacheTTL: 10 * 60 * 1000 // 10 minutes
});

// Clear cache manually
policyEngine.clearCache();

// Clear expired cache entries
policyEngine.clearExpiredCache();
```

## Real-World Examples

### Multi-Tenant SaaS

```typescript
const tenantAccessPolicy: Policy = {
  id: 'tenant-isolation',
  name: 'Tenant Data Isolation',
  effect: 'allow',
  rules: [
    {
      operator: 'AND',
      rules: [
        {
          attribute: 'user.tenantId',
          operator: 'eq',
          value: '${resource.tenantId}'
        },
        {
          attribute: 'user.status',
          operator: 'neq',
          value: 'suspended'
        }
      ]
    }
  ],
  action: 'access'
};
```

### Time-Based Access

```typescript
const businessHoursPolicy: Policy = {
  id: 'business-hours-access',
  name: 'Business Hours Only',
  effect: 'allow',
  rules: [
    {
      operator: 'AND',
      rules: [
        {
          attribute: 'environment.hour',
          operator: 'gte',
          value: 9
        },
        {
          attribute: 'environment.hour',
          operator: 'lte',
          value: 17
        },
        {
          attribute: 'environment.dayOfWeek',
          operator: 'notIn',
          value: ['saturday', 'sunday']
        }
      ]
    }
  ],
  action: 'access-financial-data'
};
```

### Role and Department Based

```typescript
const departmentPolicy: Policy = {
  id: 'hr-confidential',
  name: 'HR Confidential Access',
  effect: 'allow',
  rules: [
    {
      operator: 'OR',
      rules: [
        {
          attribute: 'user.role',
          operator: 'eq',
          value: 'hr-admin'
        },
        {
          operator: 'AND',
          rules: [
            {
              attribute: 'user.department',
              operator: 'eq',
              value: 'human-resources'
            },
            {
              attribute: 'user.clearanceLevel',
              operator: 'gte',
              value: 3
            }
          ]
        }
      ]
    }
  ],
  resourceType: 'employee-record',
  action: 'read'
};
```

### IP Whitelist

```typescript
const ipWhitelistPolicy: Policy = {
  id: 'ip-whitelist',
  name: 'IP Address Whitelist',
  effect: 'allow',
  rules: [
    {
      attribute: 'environment.ipAddress',
      operator: 'matches',
      value: '^192\\.168\\.(1|2)\\.[0-9]{1,3}$'
    }
  ],
  action: 'api-access'
};
```

## Integration with Express

```typescript
import { PolicyEngine } from '@amtarc/auth-utils/authorization/abac';
import type { Request, Response, NextFunction } from 'express';

function requirePolicy(policyId: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const context = {
      user: req.user,
      resource: {
        type: 'document',
        ...req.params
      },
      action: req.method.toLowerCase(),
      environment: {
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        currentTime: Date.now()
      }
    };

    try {
      const result = await policyEngine.evaluatePolicy(policyId, context);

      if (result.decision !== 'allow') {
        return res.status(403).json({
          error: 'Access denied',
          reason: result.reason
        });
      }

      next();
    } catch (error) {
      next(error);
    }
  };
}

// Use in routes
app.delete(
  '/documents/:id',
  requirePolicy('allow-owner-delete'),
  async (req, res) => {
    // User is authorized
    await deleteDocument(req.params.id);
    res.json({ success: true });
  }
);
```

## TypeScript Support

All ABAC types are fully typed:

```typescript
import type {
  Policy,
  PolicyContext,
  PolicyEvaluationResult,
  Rule,
  RuleGroup,
  ComparisonOperator,
  LogicalOperator,
  AttributeProvider,
  AttributeValue,
  PolicyStorageAdapter,
  PolicyEffect,
  CombiningAlgorithm
} from '@amtarc/auth-utils/authorization/abac';

// Type-safe policy definition
const policy: Policy = {
  id: 'my-policy',
  name: 'My Policy',
  effect: 'allow',
  rules: [/* ... */],
  resourceType: 'document',
  action: 'read',
  metadata: {
    createdBy: 'admin',
    version: 1
  }
};

// Type-safe context
const context: PolicyContext = {
  user: { id: 'user-123', role: 'editor' },
  resource: { id: 'doc-456', type: 'document' },
  action: 'read'
};

// Type-safe result
const result: PolicyEvaluationResult = await policyEngine.evaluatePolicy(
  policy.id,
  context
);
```

## Best Practices

### 1. Policy Naming

Use clear, descriptive policy IDs and names:

```typescript
// ✅ Good
{
  id: 'allow-owner-delete-document',
  name: 'Allow Document Owner to Delete'
}

// ❌ Avoid
{
  id: 'policy-1',
  name: 'Some Policy'
}
```

### 2. Principle of Least Privilege

Use `deny` effect for restrictions and `allow` for permissions:

```typescript
// Deny suspended users
{
  effect: 'deny',
  rules: [{ attribute: 'user.status', operator: 'eq', value: 'suspended' }]
}

// Allow specific access
{
  effect: 'allow',
  rules: [{ attribute: 'user.role', operator: 'eq', value: 'admin' }]
}
```

### 3. Policy Organization

Group related policies by resource type:

```typescript
// Document policies
await storage.savePolicy({ id: 'document-read', resourceType: 'document', action: 'read' });
await storage.savePolicy({ id: 'document-write', resourceType: 'document', action: 'write' });
await storage.savePolicy({ id: 'document-delete', resourceType: 'document', action: 'delete' });
```

### 4. Attribute Path Consistency

Use consistent attribute paths across policies:

```typescript
// ✅ Consistent
'user.id'
'user.role'
'user.department'

// ❌ Inconsistent
'user.id'
'role' // Missing 'user.' prefix
'user_department' // Different separator
```

### 5. Cache Management

Clear cache when policies change:

```typescript
await storage.savePolicy(updatedPolicy);
policyEngine.clearCache(); // Clear cache after policy update
```

## See Also

- [RBAC](/guide/authorization) - Role-Based Access Control
- [Resource-Based Access](/guide/resource-access) - Resource ownership and permissions
- [Authorization Guards](/guide/authorization-guards) - Unified authorization guards
- [API Reference](/api/core) - Complete API documentation
