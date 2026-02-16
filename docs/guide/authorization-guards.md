# Authorization Guards

Unified guards for declarative access control combining RBAC, ABAC, and resource-based permissions.

## Overview

Authorization guards provide:

- **RBAC Guards**: Permission and role validation
- **ABAC Guards**: Policy-based authorization
- **Resource Guards**: Resource ownership and access checking
- **Composable Guards**: Combine guards with AND/OR logic
- **Custom Guards**: Create domain-specific validators
- **Type Safety**: Full TypeScript support with generics
- **Error Handling**: Specific error types with detailed context

::: tip Authentication vs Authorization Guards
This page covers **authorization** guards (access control). For **authentication** guards (login/logout), see [Guards & Route Protection](/guide/guards).
:::

## Quick Start

### Installation

```bash
npm install @amtarc/auth-utils
```

### Import Guards

```typescript
import {
  requirePermission,
  requireRole,
  requirePolicy,
  requireResourceAccess,
  requireOwnership,
  combineGuardsAnd,
  combineGuardsOr,
  createCustomGuard
} from '@amtarc/auth-utils/authorization/guards';
```

## RBAC Guards

### Require Permission

Check if user has a specific permission:

```typescript
import { requirePermission } from '@amtarc/auth-utils/authorization/guards';
import { hasPermission } from '@amtarc/auth-utils/authorization';

// Define permission check function
const checkPermission = async (userId: string, permission: string) => {
  return await hasPermission(userId, permission);
};

// Use guard (throws InsufficientPermissionError if unauthorized)
await requirePermission(
  { userId: 'user-123', permission: 'posts:delete' },
  checkPermission
);

console.log('User has permission!');
```

### Require Role

Check if user has a specific role:

```typescript
import { requireRole } from '@amtarc/auth-utils/authorization/guards';
import { hasRole } from '@amtarc/auth-utils/authorization';

const checkRole = async (userId: string, role: string) => {
  return await hasRole(userId, role);
};

await requireRole(
  { userId: 'user-123', role: 'admin' },
  checkRole
);

console.log('User has role!');
```

## ABAC Guards

### Require Policy

Evaluate ABAC policy for access control:

```typescript
import { requirePolicy } from '@amtarc/auth-utils/authorization/guards';
import { PolicyEngine } from '@amtarc/auth-utils/authorization/abac';
import type { PolicyContext } from '@amtarc/auth-utils/authorization/abac';

const policyEngine = new PolicyEngine({ storage });

const checkPolicy = async (policyId: string, context: PolicyContext) => {
  const result = await policyEngine.evaluatePolicy(policyId, context);
  return result.decision === 'allow';
};

await requirePolicy(
  {
    policyId: 'allow-owner-delete',
    context: {
      user: { id: 'user-123', role: 'editor' },
      resource: { ownerId: 'user-123', type: 'document' },
      action: 'delete'
    }
  },
  checkPolicy
);

console.log('Policy evaluation passed!');
```

## Resource Guards

### Require Resource Access

Check resource-level permissions:

```typescript
import { requireResourceAccess } from '@amtarc/auth-utils/authorization/guards';
import { ResourceManager, ResourceActions } from '@amtarc/auth-utils/authorization/resource';

const resourceManager = new ResourceManager({ storage });

const checkAccess = async (userId: string, resourceId: string, action: string) => {
  return await resourceManager.canAccess(userId, resourceId, action);
};

await requireResourceAccess(
  {
    userId: 'user-123',
    resourceId: 'doc-456',
    action: ResourceActions.UPDATE
  },
  checkAccess
);

console.log('User can access resource!');
```

### Require Ownership

Validate resource ownership:

```typescript
import { requireOwnership } from '@amtarc/auth-utils/authorization/guards';
import { OwnershipPatterns } from '@amtarc/auth-utils/authorization/resource';
import type { OwnershipRule } from '@amtarc/auth-utils/authorization/resource';

const checkOwnership = async (
  userId: string, 
  resourceId: string, 
  rule: OwnershipRule
) => {
  return await resourceManager.checkOwnership(userId, resourceId, rule);
};

const ownerRule = OwnershipPatterns.createFullOwnerAccess('document');

await requireOwnership(
  {
    userId: 'user-123',
    resourceId: 'doc-456',
    rule: ownerRule
  },
  checkOwnership
);

console.log('User is owner!');
```

## Composable Guards

### Combine Guards with AND

All guards must pass:

```typescript
import { combineGuardsAnd } from '@amtarc/auth-utils/authorization/guards';

const checkIsAdminWithPermission = combineGuardsAnd([
  // Guard 1: Must have admin role
  async (context) => {
    await requireRole(
      { userId: context.userId, role: 'admin' },
      checkRole
    );
    return { granted: true };
  },
  
  // Guard 2: Must have delete permission
  async (context) => {
    await requirePermission(
      { userId: context.userId, permission: 'posts:delete' },
      checkPermission
    );
    return { granted: true };
  }
]);

// Both guards must pass
const result = await checkIsAdminWithPermission({ 
  userId: 'user-123' 
});

if (result.granted) {
  console.log('User is admin with delete permission!');
} else {
  console.log('Access denied:', result.reason);
}
```

### Combine Guards with OR

Any guard can pass:

```typescript
import { combineGuardsOr } from '@amtarc/auth-utils/authorization/guards';

const checkCanDelete = combineGuardsOr([
  // Guard 1: Owner can delete
  async (context) => {
    try {
      const isOwner = await checkOwnership(
        context.userId,
        context.resourceId,
        ownerRule
      );
      return { 
        granted: isOwner,
        reason: 'Owner access'
      };
    } catch {
      return { granted: false };
    }
  },
  
  // Guard 2: Admin can delete
  async (context) => {
    const isAdmin = await checkRole(context.userId, 'admin');
    return { 
      granted: isAdmin,
      reason: 'Admin access'
    };
  }
]);

// Either guard passing grants access
const result = await checkCanDelete({
  userId: 'user-123',
  resourceId: 'doc-456'
});

console.log(result.granted ? 'Access granted' : 'Access denied');
```

### Complex Guard Composition

Nest AND/OR for complex logic:

```typescript
// (Owner OR Admin) AND NOT Suspended
const complexGuard = combineGuardsAnd([
  // Part 1: Owner OR Admin
  combineGuardsOr([
    async (ctx) => ({
      granted: await checkOwnership(ctx.userId, ctx.resourceId, ownerRule)
    }),
    async (ctx) => ({
      granted: await checkRole(ctx.userId, 'admin')
    })
  ]),
  
  // Part 2: NOT Suspended
  async (ctx) => {
    const user = await db.users.findById(ctx.userId);
    return {
      granted: user.status !== 'suspended',
      reason: user.status === 'suspended' ? 'User suspended' : 'Active user'
    };
  }
]);

const result = await complexGuard({
  userId: 'user-123',
  resourceId: 'doc-456'
});
```

## Custom Guards

Create domain-specific authorization logic:

```typescript
import { createCustomGuard } from '@amtarc/auth-utils/authorization/guards';

// Custom business logic guard
const requireDepartmentAccess = createCustomGuard<{
  userId: string;
  resourceId: string;
  requiredDepartment: string;
}>(async (context) => {
  // Fetch user and resource
  const user = await db.users.findById(context.userId);
  const resource = await db.resources.findById(context.resourceId);

  // Check department match
  if (!user || user.department !== context.requiredDepartment) {
    return {
      granted: false,
      reason: `User not in ${context.requiredDepartment} department`
    };
  }

  if (!resource || resource.department !== context.requiredDepartment) {
    return {
      granted: false,
      reason: 'Resource not in allowed department'
    };
  }

  return {
    granted: true,
    context: {
      department: user.department,
      userRole: user.role
    }
  };
});

// Use custom guard
const result = await requireDepartmentAccess({
  userId: 'user-123',
  resourceId: 'doc-456',
  requiredDepartment: 'engineering'
});

if (result.granted) {
  console.log('Department access verified!');
}
```

### Custom Guard with External API

```typescript
const requireIPWhitelist = createCustomGuard<{
  userId: string;
  ipAddress: string;
}>(async (context) => {
  // Check IP against whitelist API
  const isAllowed = await ipWhitelistService.check(context.ipAddress);
  
  if (!isAllowed) {
    // Log security event
    await securityLog.record({
      event: 'ip_blocked',
      userId: context.userId,
      ipAddress: context.ipAddress,
      timestamp: Date.now()
    });
    
    return {
      granted: false,
      reason: `IP address ${context.ipAddress} not in whitelist`
    };
  }

  return {
    granted: true,
    context: { ipAddress: context.ipAddress }
  };
});
```

## Error Handling

Guards throw specific errors when access is denied:

```typescript
import {
  InsufficientPermissionError,
  InsufficientRoleError,
  ResourceAccessDeniedError
} from '@amtarc/auth-utils/authorization/types';

try {
  await requirePermission(
    { userId: 'user-123', permission: 'admin:delete' },
    checkPermission
  );
} catch (error) {
  if (error instanceof InsufficientPermissionError) {
    console.error('Permission denied');
    console.error('Code:', error.code); // 'INSUFFICIENT_PERMISSION'
    console.error('Context:', error.context);
    // { userId: 'user-123', permission: 'admin:delete' }
  }
}
```

### Handling Different Error Types

```typescript
try {
  await requireRole(
    { userId: 'user-123', role: 'admin' },
    checkRole
  );
} catch (error) {
  if (error instanceof InsufficientRoleError) {
    console.error('Required role:', error.context.role);
  } else if (error instanceof InsufficientPermissionError) {
    console.error('Required permission:', error.context.permission);
  } else if (error instanceof ResourceAccessDeniedError) {
    console.error('Resource access denied:', error.context.resourceId);
  } else {
    console.error('Unknown error:', error);
  }
}
```

## Real-World Examples

### Express Middleware

Simple permission guard:

```typescript
import { requirePermission } from '@amtarc/auth-utils/authorization/guards';
import type { Request, Response, NextFunction } from 'express';

function guardPermission(permission: string) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      await requirePermission(
        { userId: req.user?.id, permission },
        checkPermission
      );
      next();
    } catch (error) {
      if (error instanceof InsufficientPermissionError) {
        return res.status(403).json({
          error: 'Forbidden',
          message: error.message,
          code: error.code
        });
      }
      next(error);
    }
  };
}

// Use in routes
app.delete(
  '/posts/:id',
  guardPermission('posts:delete'),
  async (req, res) => {
    await deletePost(req.params.id);
    res.json({ success: true });
  }
);
```

### Combined Guard Middleware

Owner OR Admin can delete:

```typescript
function guardOwnerOrAdmin(resourceIdParam: string = 'id') {
  return async (req: Request, res: Response, next: NextFunction) => {
    const guard = combineGuardsOr([
      // Owner check
      async (ctx) => {
        try {
          const isOwner = await checkOwnership(
            ctx.userId,
            ctx.resourceId,
            ownerRule
          );
          return { granted: isOwner, reason: 'Owner' };
        } catch {
          return { granted: false };
        }
      },
      
      // Admin check
      async (ctx) => {
        const isAdmin = await checkRole(ctx.userId, 'admin');
        return { granted: isAdmin, reason: 'Admin' };
      }
    ]);

    try {
      const result = await guard({
        userId: req.user?.id,
        resourceId: req.params[resourceIdParam]
      });

      if (!result.granted) {
        return res.status(403).json({
          error: 'Access denied',
          reason: result.reason
        });
      }

      // Add guard result to request for downstream use
      req.guardContext = result.context;
      next();
    } catch (error) {
      next(error);
    }
  };
}

// Use in routes
app.delete('/posts/:id', guardOwnerOrAdmin(), async (req, res) => {
  // User is either owner or admin
  await deletePost(req.params.id);
  res.json({ success: true });
});
```

### Multi-Level Authorization

Authentication → Role → Resource:

```typescript
import { requireAuth } from '@amtarc/auth-utils/guards'; // Authentication guard

// Level 1: Must be authenticated
const level1 = requireAuth({
  storage,
  getSessionId: async (ctx) => ctx.request?.cookies?.session,
  onFailure: async () => ({ error: 'Not authenticated' })
});

// Level 2: Must have editor role
const level2 = async (context: any) => {
  await requireRole(
    { userId: context.userId, role: 'editor' },
    checkRole
  );
  return { granted: true };
};

// Level 3: Must own the resource
const level3 = async (context: any) => {
  await requireOwnership(
    {
      userId: context.userId,
      resourceId: context.resourceId,
      rule: ownerRule
    },
    checkOwnership
  );
  return { granted: true };
};

// Combine all levels
const fullGuard = combineGuardsAnd([level1, level2, level3]);

// All three checks must pass
app.put('/posts/:id', async (req, res, next) => {
  try {
    const result = await fullGuard({
      request: req,
      userId: req.user?.id,
      resourceId: req.params.id
    });

    if (!result.granted) {
      return res.status(403).json({ error: result.reason });
    }

    // User passed all auth checks
    const updated = await updatePost(req.params.id, req.body);
    res.json(updated);
  } catch (error) {
    next(error);
  }
});
```

### Department-Based Access

```typescript
const requireSameDepartment = createCustomGuard<{
  userId: string;
  targetUserId: string;
}>(async (context) => {
  const [user, targetUser] = await Promise.all([
    db.users.findById(context.userId),
    db.users.findById(context.targetUserId)
  ]);

  if (!user || !targetUser) {
    return { granted: false, reason: 'User not found' };
  }

  if (user.department !== targetUser.department) {
    return {
      granted: false,
      reason: 'Users in different departments'
    };
  }

  return {
    granted: true,
    context: { department: user.department }
  };
});

// Use in employee info endpoint
app.get('/employees/:id', async (req, res) => {
  const result = await requireSameDepartment({
    userId: req.user.id,
    targetUserId: req.params.id
  });

  if (!result.granted) {
    return res.status(403).json({ error: result.reason });
  }

  const employee = await getEmployee(req.params.id);
  res.json(employee);
});
```

### Time-Based Access Control

```typescript
const requireBusinessHours = createCustomGuard<{}>(async () => {
  const now = new Date();
  const hour = now.getHours();
  const day = now.getDay(); // 0 = Sunday, 6 = Saturday

  const isWeekday = day >= 1 && day <= 5;
  const isBusinessHours = hour >= 9 && hour < 17;

  if (!isWeekday || !isBusinessHours) {
    return {
      granted: false,
      reason: 'Access only allowed during business hours (Mon-Fri, 9am-5pm)'
    };
  }

  return { granted: true };
});

// Combine with other guards
const financialDataGuard = combineGuardsAnd([
  requireBusinessHours,
  async (ctx) => ({
    granted: await checkRole(ctx.userId, 'finance'),
    reason: 'Finance role required'
  })
]);

app.get('/api/financial-reports', async (req, res) => {
  const result = await financialDataGuard({ userId: req.user.id });

  if (!result.granted) {
    return res.status(403).json({ error: result.reason });
  }

  const reports = await getFinancialReports();
  res.json(reports);
});
```

## Guard Patterns

### Policy + Resource Guard

Combine ABAC policy with resource ownership:

```typescript
const policyAndResourceGuard = combineGuardsAnd([
  // Check ABAC policy
  async (context) => {
    try {
      await requirePolicy(
        {
          policyId: 'allow-department-access',
          context: {
            user: context.user,
            resource: context.resource,
            action: context.action
          }
        },
        checkPolicy
      );
      return { granted: true };
    } catch {
      return { granted: false, reason: 'Policy evaluation failed' };
    }
  },
  
  // Check resource ownership
  async (context) => {
    try {
      await requireOwnership(
        {
          userId: context.user.id,
          resourceId: context.resource.id,
          rule: ownerRule
        },
        checkOwnership
      );
      return { granted: true };
    } catch {
      return { granted: false, reason: 'Not resource owner' };
    }
  }
]);
```

### Multi-Action Resource Guard

Check multiple actions at once:

```typescript
const requireMultipleActions = (actions: string[]) => {
  return createCustomGuard<{
    userId: string;
    resourceId: string;
  }>(async (context) => {
    const checks = await Promise.all(
      actions.map(action =>
        resourceManager.canAccess(
          context.userId,
          context.resourceId,
          action
        )
      )
    );

    const allGranted = checks.every(granted => granted);

    if (!allGranted) {
      const missing = actions.filter((_, i) => !checks[i]);
      return {
        granted: false,
        reason: `Missing actions: ${missing.join(', ')}`
      };
    }

    return {
      granted: true,
      context: { actions }
    };
  });
};

// Require both read and update
const publishGuard = requireMultipleActions([
  ResourceActions.READ,
  ResourceActions.UPDATE
]);
```

## TypeScript Support

All guards are fully typed:

```typescript
import type {
  GuardContext,
  GuardResult,
  GuardFunction,
  PermissionGuardContext,
  RoleGuardContext,
  PolicyGuardContext,
  ResourceAccessGuardContext,
  OwnershipGuardContext
} from '@amtarc/auth-utils/authorization/guards';

// Type-safe guard function
const myGuard: GuardFunction<{ userId: string; resourceId: string }> = async (context) => {
  // context is typed with { userId: string; resourceId: string }
  const { userId, resourceId } = context;

  const hasAccess = await checkAccess(userId, resourceId);

  // Return typed GuardResult
  const result: GuardResult = {
    granted: hasAccess,
    reason: hasAccess ? 'Access granted' : 'Access denied',
    context: { checked: true }
  };

  return result;
};

// Type inference
const result = await myGuard({ userId: 'user-123', resourceId: 'doc-456' });
// result is typed as GuardResult
```

## Best Practices

### 1. Choose the Right Guard Type

```typescript
// ✅ Use RBAC for role-based checks
await requireRole({ userId, role: 'admin' }, checkRole);

// ✅ Use ABAC for complex attribute-based rules
await requirePolicy({ policyId: 'complex-rule', context }, checkPolicy);

// ✅ Use resource guards for ownership checks
await requireOwnership({ userId, resourceId, rule }, checkOwnership);

// ✅ Combine when needed
const guard = combineGuardsAnd([roleGuard, ownershipGuard]);
```

### 2. Compose Guards for Readability

```typescript
// ✅ Good - clear intent
const canPublish = combineGuardsAnd([
  requireAuthenticated,
  requireRole('editor'),
  requireOwnership(ownerRule)
]);

// ❌ Avoid - complex nested logic in one function
const canPublish = async (context) => {
  if (!context.authenticated) throw new Error();
  if (!await hasRole(context.userId, 'editor')) throw new Error();
  if (!await isOwner(context.userId, context.resourceId)) throw new Error();
};
```

### 3. Handle Errors Gracefully

```typescript
// ✅ Good - specific error handling
try {
  await guard(context);
} catch (error) {
  if (error instanceof InsufficientPermissionError) {
    await auditLog.record('permission_denied', error.context);
  }
  throw error;
}
```

### 4. Cache Guard Results

```typescript
// Cache expensive guard evaluations
const guardCache = new Map<string, GuardResult>();

async function cachedGuard(context: GuardContext): Promise<GuardResult> {
  const key = JSON.stringify(context);
  
  if (guardCache.has(key)) {
    return guardCache.get(key)!;
  }
  
  const result = await expensiveGuard(context);
  guardCache.set(key, result);
  
  // Clear after 1 minute
  setTimeout(() => guardCache.delete(key), 60000);
  
  return result;
}
```

### 5. Provide Clear Reason Messages

```typescript
// ✅ Good - helpful error messages
return {
  granted: false,
  reason: 'User must be in engineering department to access this resource'
};

// ❌ Avoid - vague messages
return {
  granted: false,
  reason: 'Access denied'
};
```

## Performance Considerations

### Parallel Guard Execution

Execute independent guards in parallel:

```typescript
const parallelGuards = async (context: any) => {
  // Execute all guards in parallel
  const [roleResult, permissionResult, resourceResult] = await Promise.all([
    checkRole(context.userId, 'editor').then(granted => ({ granted })),
    checkPermission(context.userId, 'posts:update').then(granted => ({ granted })),
    checkResourceAccess(context.userId, context.resourceId).then(granted => ({ granted }))
  ]);

  // All must pass
  const allGranted = [roleResult, permissionResult, resourceResult]
    .every(r => r.granted);

  return {
    granted: allGranted,
    reason: allGranted ? 'All checks passed' : 'One or more checks failed'
  };
};
```

### Short-Circuit Evaluation

```typescript
// Stop on first failure (AND logic)
const shortCircuitAnd = async (context: any) => {
  // Check least expensive first
  if (!await quickCheck(context)) {
    return { granted: false, reason: 'Quick check failed' };
  }

  // Then more expensive checks
  if (!await expensiveCheck(context)) {
    return { granted: false, reason: 'Expensive check failed' };
  }

  return { granted: true };
};

// Stop on first success (OR logic)
const shortCircuitOr = async (context: any) => {
  // Check most likely first
  if (await likelyCheck(context)) {
    return { granted: true, reason: 'Likely check passed' };
  }

  // Fallback to other checks
  if (await fallbackCheck(context)) {
    return { granted: true, reason: 'Fallback check passed' };
  }

  return { granted: false, reason: 'All checks failed' };
};
```

## See Also

- [RBAC](/guide/authorization) - Role-Based Access Control
- [ABAC](/guide/abac) - Attribute-Based Access Control
- [Resource-Based Access](/guide/resource-access) - Resource ownership and permissions
- [Authentication Guards](/guide/guards) - Login/logout guards
- [API Reference](/api/core) - Complete API documentation
