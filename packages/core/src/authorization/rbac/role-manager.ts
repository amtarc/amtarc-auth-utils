/**
 * Role management utilities
 * Handles role definition, assignment, and permission management
 */

import type {
  Role,
  RoleId,
  PermissionId,
  UserRole,
  RBACStorageAdapter,
  RoleOptions,
} from './types';
import type { UserId } from '../types';
import { RoleExistsError, RoleNotFoundError } from '../types';

export interface RoleManagerOptions {
  storage: RBACStorageAdapter;
}

export class RoleManager {
  constructor(private options: RoleManagerOptions) {}

  /**
   * Define a new role
   */
  async defineRole(
    role: Omit<Role, 'permissions' | 'parents' | 'createdAt' | 'updatedAt'> & {
      permissions?: string[];
      parents?: string[];
    }
  ): Promise<Role> {
    // Check if role already exists
    const existing = await this.options.storage.getRole(role.id);
    if (existing) {
      throw new RoleExistsError(role.id);
    }

    const newRole: Role = {
      id: role.id,
      name: role.name,
      permissions: new Set(role.permissions || []),
      ...(role.description !== undefined && { description: role.description }),
      ...(role.parents !== undefined && { parents: new Set(role.parents) }),
      ...(role.metadata !== undefined && { metadata: role.metadata }),
    };

    await this.options.storage.saveRole(newRole);
    return newRole;
  }

  /**
   * Update existing role
   */
  async updateRole(
    id: RoleId,
    updates: Partial<Omit<Role, 'id' | 'permissions' | 'parents'>> & {
      permissions?: string[];
      parents?: string[];
    }
  ): Promise<Role> {
    const existing = await this.options.storage.getRole(id);
    if (!existing) {
      throw new RoleNotFoundError(id);
    }

    const updated: Role = {
      id, // Ensure ID doesn't change
      name: updates.name ?? existing.name,
      permissions: updates.permissions
        ? new Set(updates.permissions)
        : existing.permissions,
      ...(existing.createdAt !== undefined && {
        createdAt: existing.createdAt,
      }),
      ...(existing.updatedAt !== undefined && {
        updatedAt: existing.updatedAt,
      }),
      ...(updates.description !== undefined
        ? { description: updates.description }
        : existing.description !== undefined
          ? { description: existing.description }
          : {}),
      ...(updates.parents !== undefined
        ? { parents: new Set(updates.parents) }
        : existing.parents !== undefined
          ? { parents: existing.parents }
          : {}),
      ...(updates.metadata !== undefined
        ? { metadata: updates.metadata }
        : existing.metadata !== undefined
          ? { metadata: existing.metadata }
          : {}),
    };

    await this.options.storage.saveRole(updated);
    return updated;
  }

  /**
   * Delete a role
   */
  async deleteRole(id: RoleId): Promise<void> {
    const existing = await this.options.storage.getRole(id);
    if (!existing) {
      throw new RoleNotFoundError(id);
    }

    await this.options.storage.deleteRole(id);
  }

  /**
   * Get role by ID
   */
  async getRole(id: RoleId): Promise<Role | null> {
    return this.options.storage.getRole(id);
  }

  /**
   * List all roles
   */
  async listRoles(): Promise<Role[]> {
    return this.options.storage.listRoles();
  }

  /**
   * Grant permission to role
   */
  async grantPermission(
    roleId: RoleId,
    permissionId: PermissionId
  ): Promise<void> {
    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      throw new RoleNotFoundError(roleId);
    }

    role.permissions.add(permissionId);
    await this.options.storage.saveRole(role);
  }

  /**
   * Grant multiple permissions to role
   */
  async grantPermissions(
    roleId: RoleId,
    permissionIds: PermissionId[]
  ): Promise<void> {
    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      throw new RoleNotFoundError(roleId);
    }

    for (const permissionId of permissionIds) {
      role.permissions.add(permissionId);
    }
    await this.options.storage.saveRole(role);
  }

  /**
   * Revoke permission from role
   */
  async revokePermission(
    roleId: RoleId,
    permissionId: PermissionId
  ): Promise<void> {
    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      throw new RoleNotFoundError(roleId);
    }

    role.permissions.delete(permissionId);
    await this.options.storage.saveRole(role);
  }

  /**
   * Revoke multiple permissions from role
   */
  async revokePermissions(
    roleId: RoleId,
    permissionIds: PermissionId[]
  ): Promise<void> {
    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      throw new RoleNotFoundError(roleId);
    }

    for (const permissionId of permissionIds) {
      role.permissions.delete(permissionId);
    }
    await this.options.storage.saveRole(role);
  }

  /**
   * Get all permissions for a role (including inherited)
   */
  async getRolePermissions(
    roleId: RoleId,
    options: RoleOptions = {}
  ): Promise<Set<PermissionId>> {
    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      return new Set();
    }

    const permissions = new Set(role.permissions);

    // Include inherited permissions if requested
    if (options.includeInherited && role.parents) {
      const maxDepth = options.maxDepth || 10;
      const inherited = await this.getInheritedPermissions(role, 0, maxDepth);
      for (const perm of inherited) {
        permissions.add(perm);
      }
    }

    return permissions;
  }

  /**
   * Assign role to user
   */
  async assignRole(
    userId: UserId,
    roleId: RoleId,
    options?: {
      scope?: string;
      expiresAt?: number;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void> {
    // Verify role exists
    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      throw new RoleNotFoundError(roleId);
    }

    const assignment: UserRole = {
      userId,
      roleId,
      assignedAt: Date.now(),
      ...(options?.scope !== undefined && { scope: options.scope }),
      ...(options?.expiresAt !== undefined && { expiresAt: options.expiresAt }),
      ...(options?.metadata !== undefined && { metadata: options.metadata }),
    };

    await this.options.storage.assignUserRole(assignment);
  }

  /**
   * Remove role from user
   */
  async removeRole(
    userId: UserId,
    roleId: RoleId,
    scope?: string
  ): Promise<void> {
    await this.options.storage.removeUserRole(userId, roleId, scope);
  }

  /**
   * Get all roles for a user
   */
  async getUserRoles(userId: UserId): Promise<UserRole[]> {
    return this.options.storage.getUserRoles(userId);
  }

  /**
   * Check if user has specific role
   */
  async hasRole(
    userId: UserId,
    roleId: RoleId,
    scope?: string
  ): Promise<boolean> {
    const assignments = await this.options.storage.getUserRoles(userId);

    return assignments.some(
      (a) => a.roleId === roleId && (scope === undefined || a.scope === scope)
    );
  }

  /**
   * Check if user has any of the specified roles
   */
  async hasAnyRole(
    userId: UserId,
    roleIds: RoleId[],
    scope?: string
  ): Promise<boolean> {
    const assignments = await this.options.storage.getUserRoles(userId);

    return assignments.some(
      (a) =>
        roleIds.includes(a.roleId) && (scope === undefined || a.scope === scope)
    );
  }

  /**
   * Check if user has all of the specified roles
   */
  async hasAllRoles(
    userId: UserId,
    roleIds: RoleId[],
    scope?: string
  ): Promise<boolean> {
    const assignments = await this.options.storage.getUserRoles(userId);
    const userRoleIds = assignments
      .filter((a) => scope === undefined || a.scope === scope)
      .map((a) => a.roleId);

    return roleIds.every((roleId) => userRoleIds.includes(roleId));
  }

  /**
   * Get all users with a specific role
   */
  async getRoleUsers(roleId: RoleId): Promise<UserId[]> {
    return this.options.storage.listUsersByRole(roleId);
  }

  /**
   * Get inherited permissions recursively
   */
  private async getInheritedPermissions(
    role: Role,
    depth: number,
    maxDepth: number,
    visited = new Set<RoleId>()
  ): Promise<Set<PermissionId>> {
    const permissions = new Set<PermissionId>();

    // Prevent infinite recursion
    if (depth >= maxDepth) {
      return permissions;
    }

    // Prevent circular dependencies
    if (visited.has(role.id)) {
      return permissions;
    }

    visited.add(role.id);

    if (!role.parents || role.parents.size === 0) {
      return permissions;
    }

    // Get permissions from parent roles
    for (const parentId of role.parents) {
      const parent = await this.options.storage.getRole(parentId);
      if (!parent) {
        continue;
      }

      // Add parent's direct permissions
      for (const perm of parent.permissions) {
        permissions.add(perm);
      }

      // Recursively get parent's inherited permissions
      const inherited = await this.getInheritedPermissions(
        parent,
        depth + 1,
        maxDepth,
        visited
      );
      for (const perm of inherited) {
        permissions.add(perm);
      }
    }

    return permissions;
  }
}
