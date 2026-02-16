/**
 * Authorization guards
 * Unified guards for RBAC, ABAC, and resource-based authorization
 */

import type { UserId, ResourceId } from '../types';
import type { RoleId, PermissionId } from '../rbac/types';
import type { Policy, PolicyContext } from '../abac/types';
import type { ResourceAction } from '../resource/types';
import {
  InsufficientPermissionError,
  InsufficientRoleError,
  ResourceAccessDeniedError,
} from '../types';

/**
 * Guard context - information available to guards
 */
export interface GuardContext {
  userId?: UserId;
  resourceId?: ResourceId;
  resourceType?: string;
  action?: string;
  [key: string]: unknown;
}

/**
 * Guard result
 */
export interface GuardResult {
  granted: boolean;
  reason?: string;
  context?: Record<string, unknown>;
}

/**
 * Guard function type
 */
export type GuardFunction = (
  context: GuardContext
) => Promise<GuardResult> | GuardResult;

/**
 * RBAC Permission Guard
 * Requires user to have specific permission(s)
 */
export function requirePermission(
  requiredPermissions: PermissionId | PermissionId[],
  checkFn: (userId: UserId, permissions: PermissionId[]) => Promise<boolean>
): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    if (!context.userId) {
      return {
        granted: false,
        reason: 'No user ID provided',
      };
    }

    const permissions = Array.isArray(requiredPermissions)
      ? requiredPermissions
      : [requiredPermissions];

    const hasPermission = await checkFn(context.userId, permissions);

    if (!hasPermission) {
      throw new InsufficientPermissionError(permissions);
    }

    return {
      granted: true,
      reason: 'Permission check passed',
    };
  };
}

/**
 * RBAC Role Guard
 * Requires user to have specific role(s)
 */
export function requireRole(
  requiredRoles: RoleId | RoleId[],
  checkFn: (userId: UserId, roles: RoleId[]) => Promise<boolean>
): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    if (!context.userId) {
      return {
        granted: false,
        reason: 'No user ID provided',
      };
    }

    const roles = Array.isArray(requiredRoles)
      ? requiredRoles
      : [requiredRoles];

    const hasRole = await checkFn(context.userId, roles);

    if (!hasRole) {
      throw new InsufficientRoleError(roles);
    }

    return {
      granted: true,
      reason: 'Role check passed',
    };
  };
}

/**
 * ABAC Policy Guard
 * Evaluates ABAC policy
 */
export function requirePolicy(
  policy: Policy,
  evaluateFn: (
    policy: Policy,
    context: PolicyContext
  ) => Promise<{ granted: boolean; reason?: string }>
): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    const result = await evaluateFn(policy, context as PolicyContext);

    if (!result.granted) {
      throw new InsufficientPermissionError(policy.id, {
        policy: policy.name,
        reason: result.reason,
      });
    }

    return {
      granted: true,
      reason: result.reason || 'Policy evaluation passed',
    };
  };
}

/**
 * Resource Access Guard
 * Checks resource-based permissions
 */
export function requireResourceAccess(
  action: ResourceAction,
  checkFn: (
    userId: UserId,
    resourceId: ResourceId,
    action: ResourceAction
  ) => Promise<boolean>
): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    if (!context.userId) {
      return {
        granted: false,
        reason: 'No user ID provided',
      };
    }

    if (!context.resourceId) {
      return {
        granted: false,
        reason: 'No resource ID provided',
      };
    }

    const hasAccess = await checkFn(context.userId, context.resourceId, action);

    if (!hasAccess) {
      throw new ResourceAccessDeniedError(context.resourceId, action, {
        userId: context.userId,
        resourceType: context.resourceType,
      });
    }

    return {
      granted: true,
      reason: 'Resource access granted',
    };
  };
}

/**
 * Ownership Guard
 * Checks if user owns the resource
 */
export function requireOwnership(
  getOwner: (resourceId: ResourceId) => Promise<UserId | null>
): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    if (!context.userId) {
      return {
        granted: false,
        reason: 'No user ID provided',
      };
    }

    if (!context.resourceId) {
      return {
        granted: false,
        reason: 'No resource ID provided',
      };
    }

    const ownerId = await getOwner(context.resourceId);

    if (ownerId !== context.userId) {
      throw new ResourceAccessDeniedError(context.resourceId, 'ownership', {
        userId: context.userId,
        ownerId,
      });
    }

    return {
      granted: true,
      reason: 'User is resource owner',
    };
  };
}

/**
 * Combine multiple guards with AND logic
 * All guards must pass
 */
export function combineGuardsAnd(...guards: GuardFunction[]): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    const results: GuardResult[] = [];

    for (const guard of guards) {
      const result = await guard(context);
      results.push(result);

      if (!result.granted) {
        const failResult: GuardResult = {
          granted: false,
          reason: result.reason || 'Guard check failed',
        };
        if (result.context) {
          failResult.context = result.context;
        }
        return failResult;
      }
    }

    const successResult: GuardResult = {
      granted: true,
      reason: 'All guard checks passed',
    };
    const mergedContext = Object.assign(
      {},
      ...results.map((r) => r.context || {})
    );
    if (Object.keys(mergedContext).length > 0) {
      successResult.context = mergedContext;
    }
    return successResult;
  };
}

/**
 * Combine multiple guards with OR logic
 * At least one guard must pass
 */
export function combineGuardsOr(...guards: GuardFunction[]): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    const errors: string[] = [];

    for (const guard of guards) {
      try {
        const result = await guard(context);
        if (result.granted) {
          return result;
        }
        errors.push(result.reason || 'Unknown reason');
      } catch (error) {
        errors.push(error instanceof Error ? error.message : 'Unknown error');
      }
    }

    return {
      granted: false,
      reason: `All guards failed: ${errors.join(', ')}`,
    };
  };
}

/**
 * Custom guard with function
 */
export function createCustomGuard(
  guardFn: (context: GuardContext) => Promise<boolean> | boolean,
  errorMessage?: string
): GuardFunction {
  return async (context: GuardContext): Promise<GuardResult> => {
    const granted = await guardFn(context);

    if (!granted) {
      throw new InsufficientPermissionError('custom', {
        message: errorMessage || 'Custom guard check failed',
      });
    }

    return {
      granted: true,
      reason: 'Custom guard passed',
    };
  };
}
