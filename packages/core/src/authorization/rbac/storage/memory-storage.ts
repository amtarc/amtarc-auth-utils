/**
 * In-memory RBAC storage adapter
 * For development and testing, or single-server deployments
 */

import type {
  RBACStorageAdapter,
  Role,
  Permission,
  UserRole,
  RoleId,
  PermissionId,
} from '../types';
import type { UserId } from '../../types';

export class MemoryRBACStorage implements RBACStorageAdapter {
  private roles = new Map<RoleId, Role>();
  private permissions = new Map<PermissionId, Permission>();
  private userRoles = new Map<UserId, UserRole[]>();
  private roleUsers = new Map<RoleId, Set<UserId>>();

  // Role operations
  async getRole(roleId: RoleId): Promise<Role | null> {
    return this.roles.get(roleId) || null;
  }

  async saveRole(role: Role): Promise<void> {
    // Update timestamp
    const existingRole = this.roles.get(role.id);
    const now = Date.now();

    const updatedRole: Role = {
      id: role.id,
      name: role.name,
      permissions: new Set(role.permissions),
      createdAt: existingRole?.createdAt || now,
      updatedAt: now,
      ...(role.description !== undefined && { description: role.description }),
      ...(role.parents !== undefined && { parents: new Set(role.parents) }),
      ...(role.metadata !== undefined && { metadata: role.metadata }),
    };

    this.roles.set(role.id, updatedRole);
  }

  async deleteRole(roleId: RoleId): Promise<void> {
    this.roles.delete(roleId);

    // Clean up user-role assignments
    for (const [userId, assignments] of this.userRoles.entries()) {
      const filtered = assignments.filter((a) => a.roleId !== roleId);
      if (filtered.length > 0) {
        this.userRoles.set(userId, filtered);
      } else {
        this.userRoles.delete(userId);
      }
    }

    this.roleUsers.delete(roleId);
  }

  async listRoles(): Promise<Role[]> {
    return Array.from(this.roles.values());
  }

  // Permission operations
  async getPermission(permissionId: PermissionId): Promise<Permission | null> {
    return this.permissions.get(permissionId) || null;
  }

  async savePermission(permission: Permission): Promise<void> {
    this.permissions.set(permission.id, permission);
  }

  async deletePermission(permissionId: PermissionId): Promise<void> {
    this.permissions.delete(permissionId);

    // Remove from all roles
    for (const role of this.roles.values()) {
      role.permissions.delete(permissionId);
    }
  }

  async listPermissions(): Promise<Permission[]> {
    return Array.from(this.permissions.values());
  }

  // User-role assignments
  async getUserRoles(userId: UserId): Promise<UserRole[]> {
    const assignments = this.userRoles.get(userId) || [];

    // Filter out expired assignments
    const now = Date.now();
    return assignments.filter((a) => !a.expiresAt || a.expiresAt > now);
  }

  async assignUserRole(assignment: UserRole): Promise<void> {
    const userId = assignment.userId;
    const roleId = assignment.roleId;

    // Get existing assignments
    const assignments = this.userRoles.get(userId) || [];

    // Check if assignment already exists (same role and scope)
    const existingIndex = assignments.findIndex(
      (a) => a.roleId === roleId && a.scope === assignment.scope
    );

    if (existingIndex >= 0) {
      // Update existing assignment
      assignments[existingIndex] = assignment;
    } else {
      // Add new assignment
      assignments.push(assignment);
    }

    this.userRoles.set(userId, assignments);

    // Update reverse index
    if (!this.roleUsers.has(roleId)) {
      this.roleUsers.set(roleId, new Set());
    }
    const roleUserSet = this.roleUsers.get(roleId);
    if (roleUserSet) {
      roleUserSet.add(userId);
    }
  }

  async removeUserRole(
    userId: UserId,
    roleId: RoleId,
    scope?: string
  ): Promise<void> {
    const assignments = this.userRoles.get(userId) || [];

    const filtered = assignments.filter(
      (a) =>
        !(a.roleId === roleId && (scope === undefined || a.scope === scope))
    );

    if (filtered.length > 0) {
      this.userRoles.set(userId, filtered);
    } else {
      this.userRoles.delete(userId);
    }

    // Update reverse index: only remove user from roleUsers if they
    // no longer have ANY assignment for this roleId (in any scope)
    const userStillHasRole = filtered.some((a) => a.roleId === roleId);
    if (!userStillHasRole) {
      const users = this.roleUsers.get(roleId);
      if (users) {
        users.delete(userId);
        if (users.size === 0) {
          this.roleUsers.delete(roleId);
        }
      }
    }
  }

  async listUsersByRole(roleId: RoleId): Promise<UserId[]> {
    const usersForRole = this.roleUsers.get(roleId);
    if (!usersForRole) {
      return [];
    }

    const now = Date.now();
    const activeUsers: UserId[] = [];

    // Filter out users with expired assignments
    for (const userId of usersForRole) {
      const assignments = this.userRoles.get(userId) || [];
      const hasActiveAssignment = assignments.some(
        (a) => a.roleId === roleId && (!a.expiresAt || a.expiresAt > now)
      );

      if (hasActiveAssignment) {
        activeUsers.push(userId);
      } else {
        // Clean up stale reverse index entries
        usersForRole.delete(userId);
      }
    }

    // Clean up empty role entry
    if (usersForRole.size === 0) {
      this.roleUsers.delete(roleId);
    }

    return activeUsers;
  }

  /**
   * Clear all data (useful for testing)
   */
  clear(): void {
    this.roles.clear();
    this.permissions.clear();
    this.userRoles.clear();
    this.roleUsers.clear();
  }
}
