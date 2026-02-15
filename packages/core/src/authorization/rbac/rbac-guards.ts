/**
 * RBAC guards for route and resource protection
 */

import type { RoleId, PermissionId, PermissionCheckOptions } from './types';
import type { UserId } from '../types';
import type { RoleManager } from './role-manager';
import { InsufficientRoleError, InsufficientPermissionError } from '../types';

export interface RBACGuardContext {
  userId: UserId;
  scope?: string;
  [key: string]: unknown;
}

export interface RBACGuardOptions {
  roleManager: RoleManager;
  /** Throw error on authorization failure (default: true) */
  throwOnFailure?: boolean;
  /** Custom error handler */
  onError?: (error: Error, context: RBACGuardContext) => void | Promise<void>;
}

export class RBACGuards {
  constructor(private options: RBACGuardOptions) {}

  /**
   * Require user to have specific role
   */
  async requireRole(
    context: RBACGuardContext,
    roleId: RoleId
  ): Promise<boolean> {
    const hasRole = await this.options.roleManager.hasRole(
      context.userId,
      roleId,
      context.scope
    );

    if (!hasRole) {
      const error = new InsufficientRoleError(roleId, { ...context });
      await this.handleError(error, context);
      return false;
    }

    return true;
  }

  /**
   * Require user to have any of the specified roles
   */
  async requireAnyRole(
    context: RBACGuardContext,
    roleIds: RoleId[]
  ): Promise<boolean> {
    const hasAnyRole = await this.options.roleManager.hasAnyRole(
      context.userId,
      roleIds,
      context.scope
    );

    if (!hasAnyRole) {
      const error = new InsufficientRoleError(roleIds, { ...context });
      await this.handleError(error, context);
      return false;
    }

    return true;
  }

  /**
   * Require user to have all specified roles
   */
  async requireAllRoles(
    context: RBACGuardContext,
    roleIds: RoleId[]
  ): Promise<boolean> {
    const hasAllRoles = await this.options.roleManager.hasAllRoles(
      context.userId,
      roleIds,
      context.scope
    );

    if (!hasAllRoles) {
      const error = new InsufficientRoleError(roleIds, { ...context });
      await this.handleError(error, context);
      return false;
    }

    return true;
  }

  /**
   * Require user to have specific permission
   */
  async requirePermission(
    context: RBACGuardContext,
    permissionId: PermissionId,
    options?: PermissionCheckOptions
  ): Promise<boolean> {
    const hasPermission = await this.hasPermission(
      context.userId,
      permissionId,
      options
    );

    if (!hasPermission) {
      const error = new InsufficientPermissionError(permissionId, {
        ...context,
      });
      await this.handleError(error, context);
      return false;
    }

    return true;
  }

  /**
   * Require user to have any of the specified permissions
   */
  async requireAnyPermission(
    context: RBACGuardContext,
    permissionIds: PermissionId[],
    options?: PermissionCheckOptions
  ): Promise<boolean> {
    for (const permissionId of permissionIds) {
      const hasPermission = await this.hasPermission(
        context.userId,
        permissionId,
        options
      );
      if (hasPermission) {
        return true;
      }
    }

    const error = new InsufficientPermissionError(permissionIds, {
      ...context,
    });
    await this.handleError(error, context);
    return false;
  }

  /**
   * Require user to have all specified permissions
   */
  async requireAllPermissions(
    context: RBACGuardContext,
    permissionIds: PermissionId[],
    options?: PermissionCheckOptions
  ): Promise<boolean> {
    for (const permissionId of permissionIds) {
      const hasPermission = await this.hasPermission(
        context.userId,
        permissionId,
        options
      );
      if (!hasPermission) {
        const error = new InsufficientPermissionError(permissionIds, {
          ...context,
        });
        await this.handleError(error, context);
        return false;
      }
    }

    return true;
  }

  /**
   * Check if user has specific permission
   */
  async hasPermission(
    userId: UserId,
    permissionId: PermissionId,
    options?: PermissionCheckOptions
  ): Promise<boolean> {
    const checkOptions: PermissionCheckOptions = {
      includeInherited: true,
      ...options,
    };

    // Get all user roles
    const userRoles = await this.options.roleManager.getUserRoles(userId);

    // Filter by scope if specified
    const relevantRoles = checkOptions.scope
      ? userRoles.filter((ur) => ur.scope === checkOptions.scope)
      : userRoles;

    // Check each role's permissions
    for (const userRole of relevantRoles) {
      const permissions = await this.options.roleManager.getRolePermissions(
        userRole.roleId,
        checkOptions.includeInherited !== undefined
          ? { includeInherited: checkOptions.includeInherited }
          : {}
      );

      if (permissions.has(permissionId)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if user has multiple permissions
   */
  async hasPermissions(
    userId: UserId,
    permissionIds: PermissionId[],
    options?: PermissionCheckOptions
  ): Promise<boolean> {
    const mode = options?.mode || 'AND';

    if (mode === 'OR') {
      for (const permissionId of permissionIds) {
        const hasPermission = await this.hasPermission(
          userId,
          permissionId,
          options
        );
        if (hasPermission) {
          return true;
        }
      }
      return false;
    } else {
      // AND mode
      for (const permissionId of permissionIds) {
        const hasPermission = await this.hasPermission(
          userId,
          permissionId,
          options
        );
        if (!hasPermission) {
          return false;
        }
      }
      return true;
    }
  }

  /**
   * Handle authorization error
   */
  private async handleError(
    error: Error,
    context: RBACGuardContext
  ): Promise<void> {
    if (this.options.onError) {
      await this.options.onError(error, context);
    }

    const throwOnFailure = this.options.throwOnFailure ?? true;
    if (throwOnFailure) {
      throw error;
    }
  }
}

/**
 * Create RBAC guard instance
 */
export function createRBACGuards(options: RBACGuardOptions): RBACGuards {
  return new RBACGuards(options);
}
