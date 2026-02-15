/**
 * Functional API for RBAC operations
 * Provides a simpler, stateless API similar to session/security modules
 */

import type {
  Role,
  RoleId,
  Permission,
  PermissionId,
  UserRole,
  RBACStorageAdapter,
  RoleOptions,
  PermissionCheckOptions,
} from './types';
import type { UserId } from '../types';
import { PermissionManager } from './permission-manager';
import { RoleManager } from './role-manager';
import { RBACGuards } from './rbac-guards';

/**
 * Global storage instance (can be set by user)
 */
let defaultStorage: RBACStorageAdapter | null = null;

/**
 * Set the default storage adapter for functional RBAC operations
 * Call this once at app initialization
 */
export function setDefaultRBACStorage(storage: RBACStorageAdapter): void {
  defaultStorage = storage;
}

/**
 * Get or throw if storage not configured
 */
function getStorage(): RBACStorageAdapter {
  if (!defaultStorage) {
    throw new Error(
      'RBAC storage not configured. Call setDefaultRBACStorage() first.'
    );
  }
  return defaultStorage;
}

// =============================================================================
// Permission Management Functions
// =============================================================================

/**
 * Define a new permission
 */
export async function definePermission(
  permission: Omit<Permission, 'id'> & { id?: PermissionId }
): Promise<Permission> {
  const manager = new PermissionManager({ storage: getStorage() });
  return manager.definePermission(permission);
}

/**
 * Define multiple permissions at once
 */
export async function definePermissions(
  permissions: Array<Omit<Permission, 'id'> & { id?: PermissionId }>
): Promise<Permission[]> {
  const manager = new PermissionManager({ storage: getStorage() });
  return manager.definePermissions(permissions);
}

/**
 * Update existing permission
 */
export async function updatePermission(
  id: PermissionId,
  updates: Partial<Omit<Permission, 'id'>>
): Promise<Permission> {
  const manager = new PermissionManager({ storage: getStorage() });
  return manager.updatePermission(id, updates);
}

/**
 * Delete a permission
 */
export async function deletePermission(id: PermissionId): Promise<void> {
  const manager = new PermissionManager({ storage: getStorage() });
  return manager.deletePermission(id);
}

/**
 * Get permission by ID
 */
export async function getPermission(
  id: PermissionId
): Promise<Permission | null> {
  const manager = new PermissionManager({ storage: getStorage() });
  return manager.getPermission(id);
}

/**
 * List all permissions
 */
export async function listPermissions(): Promise<Permission[]> {
  const manager = new PermissionManager({ storage: getStorage() });
  return manager.listPermissions();
}

// =============================================================================
// Role Management Functions
// =============================================================================

/**
 * Define a new role
 */
export async function defineRole(
  role: Omit<Role, 'permissions' | 'parents' | 'createdAt' | 'updatedAt'> & {
    permissions?: string[];
    parents?: string[];
  }
): Promise<Role> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.defineRole(role);
}

/**
 * Update existing role
 */
export async function updateRole(
  id: RoleId,
  updates: Partial<Omit<Role, 'id' | 'permissions' | 'parents'>> & {
    permissions?: string[];
    parents?: string[];
  }
): Promise<Role> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.updateRole(id, updates);
}

/**
 * Delete a role
 */
export async function deleteRole(id: RoleId): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.deleteRole(id);
}

/**
 * Get role by ID
 */
export async function getRole(id: RoleId): Promise<Role | null> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.getRole(id);
}

/**
 * List all roles
 */
export async function listRoles(): Promise<Role[]> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.listRoles();
}

/**
 * Grant permission to role
 */
export async function grantPermission(
  roleId: RoleId,
  permissionId: PermissionId
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.grantPermission(roleId, permissionId);
}

/**
 * Grant multiple permissions to role
 */
export async function grantPermissions(
  roleId: RoleId,
  permissionIds: PermissionId[]
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.grantPermissions(roleId, permissionIds);
}

/**
 * Revoke permission from role
 */
export async function revokePermission(
  roleId: RoleId,
  permissionId: PermissionId
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.revokePermission(roleId, permissionId);
}

/**
 * Get all permissions for a role (including inherited)
 */
export async function getRolePermissions(
  roleId: RoleId,
  options?: RoleOptions
): Promise<Set<PermissionId>> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.getRolePermissions(roleId, options);
}

// =============================================================================
// User-Role Assignment Functions
// =============================================================================

/**
 * Assign role to user
 */
export async function assignRole(
  userId: UserId,
  roleId: RoleId,
  options?: {
    scope?: string;
    expiresAt?: number;
    metadata?: Record<string, unknown>;
  }
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.assignRole(userId, roleId, options);
}

/**
 * Remove role from user
 */
export async function removeRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.removeRole(userId, roleId, scope);
}

/**
 * Check if user has specific role
 */
export async function hasRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<boolean> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.hasRole(userId, roleId, scope);
}

/**
 * Check if user has any of the specified roles
 */
export async function hasAnyRole(
  userId: UserId,
  roleIds: RoleId[],
  scope?: string
): Promise<boolean> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.hasAnyRole(userId, roleIds, scope);
}

/**
 * Check if user has all specified roles
 */
export async function hasAllRoles(
  userId: UserId,
  roleIds: RoleId[],
  scope?: string
): Promise<boolean> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.hasAllRoles(userId, roleIds, scope);
}

/**
 * Get all role assignments for a user
 */
export async function getUserRoles(userId: UserId): Promise<UserRole[]> {
  const manager = new RoleManager({ storage: getStorage() });
  return manager.getUserRoles(userId);
}

// =============================================================================
// Permission Check Functions
// =============================================================================

/**
 * Check if user has specific permission
 */
export async function hasPermission(
  userId: UserId,
  permissionId: PermissionId,
  options?: PermissionCheckOptions
): Promise<boolean> {
  const manager = new RoleManager({ storage: getStorage() });
  const guards = new RBACGuards({
    roleManager: manager,
    throwOnFailure: false,
  });
  return guards.hasPermission(userId, permissionId, options);
}

/**
 * Check if user has any of the specified permissions
 */
export async function hasAnyPermission(
  userId: UserId,
  permissionIds: PermissionId[],
  options?: PermissionCheckOptions
): Promise<boolean> {
  const manager = new RoleManager({ storage: getStorage() });
  const guards = new RBACGuards({
    roleManager: manager,
    throwOnFailure: false,
  });

  for (const permissionId of permissionIds) {
    const has = await guards.hasPermission(userId, permissionId, options);
    if (has) return true;
  }
  return false;
}

/**
 * Check if user has all specified permissions
 */
export async function hasAllPermissions(
  userId: UserId,
  permissionIds: PermissionId[],
  options?: PermissionCheckOptions
): Promise<boolean> {
  const manager = new RoleManager({ storage: getStorage() });
  const guards = new RBACGuards({
    roleManager: manager,
    throwOnFailure: false,
  });

  for (const permissionId of permissionIds) {
    const has = await guards.hasPermission(userId, permissionId, options);
    if (!has) return false;
  }
  return true;
}

/**
 * Require user to have specific permission (throws if not authorized)
 */
export async function requirePermission(
  userId: UserId,
  permissionId: PermissionId,
  options?: PermissionCheckOptions
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  const guards = new RBACGuards({ roleManager: manager });

  const context = {
    userId,
    ...(options?.scope !== undefined && { scope: options.scope }),
  };

  await guards.requirePermission(context, permissionId, options);
}

/**
 * Require user to have specific role (throws if not authorized)
 */
export async function requireRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<void> {
  const manager = new RoleManager({ storage: getStorage() });
  const guards = new RBACGuards({ roleManager: manager });

  const context = {
    userId,
    ...(scope !== undefined && { scope }),
  };

  await guards.requireRole(context, roleId);
}
