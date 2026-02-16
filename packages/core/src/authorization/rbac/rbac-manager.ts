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
 * Cached manager instances (recreated when storage changes)
 */
let cachedPermissionManager: PermissionManager | null = null;
let cachedRoleManager: RoleManager | null = null;
let cachedGuards: RBACGuards | null = null;

/**
 * Set the default storage adapter for functional RBAC operations
 * Call this once at app initialization
 */
export function setDefaultRBACStorage(storage: RBACStorageAdapter): void {
  defaultStorage = storage;
  // Clear cached instances when storage changes
  cachedPermissionManager = null;
  cachedRoleManager = null;
  cachedGuards = null;
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

/**
 * Get cached PermissionManager instance
 */
function getPermissionManager(): PermissionManager {
  if (!cachedPermissionManager) {
    cachedPermissionManager = new PermissionManager({ storage: getStorage() });
  }
  return cachedPermissionManager;
}

/**
 * Get cached RoleManager instance
 */
function getRoleManager(): RoleManager {
  if (!cachedRoleManager) {
    cachedRoleManager = new RoleManager({ storage: getStorage() });
  }
  return cachedRoleManager;
}

/**
 * Get cached RBACGuards instance
 */
function getGuards(): RBACGuards {
  if (!cachedGuards) {
    cachedGuards = new RBACGuards({ roleManager: getRoleManager() });
  }
  return cachedGuards;
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
  return getPermissionManager().definePermission(permission);
}

/**
 * Define multiple permissions at once
 */
export async function definePermissions(
  permissions: Array<Omit<Permission, 'id'> & { id?: PermissionId }>
): Promise<Permission[]> {
  return getPermissionManager().definePermissions(permissions);
}

/**
 * Update existing permission
 */
export async function updatePermission(
  id: PermissionId,
  updates: Partial<Omit<Permission, 'id'>>
): Promise<Permission> {
  return getPermissionManager().updatePermission(id, updates);
}

/**
 * Delete a permission
 */
export async function deletePermission(id: PermissionId): Promise<void> {
  return getPermissionManager().deletePermission(id);
}

/**
 * Get permission by ID
 */
export async function getPermission(
  id: PermissionId
): Promise<Permission | null> {
  return getPermissionManager().getPermission(id);
}

/**
 * List all permissions
 */
export async function listPermissions(): Promise<Permission[]> {
  return getPermissionManager().listPermissions();
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
  return getRoleManager().defineRole(role);
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
  return getRoleManager().updateRole(id, updates);
}

/**
 * Delete a role
 */
export async function deleteRole(id: RoleId): Promise<void> {
  return getRoleManager().deleteRole(id);
}

/**
 * Get role by ID
 */
export async function getRole(id: RoleId): Promise<Role | null> {
  return getRoleManager().getRole(id);
}

/**
 * List all roles
 */
export async function listRoles(): Promise<Role[]> {
  return getRoleManager().listRoles();
}

/**
 * Grant permission to role
 */
export async function grantPermission(
  roleId: RoleId,
  permissionId: PermissionId
): Promise<void> {
  return getRoleManager().grantPermission(roleId, permissionId);
}

/**
 * Grant multiple permissions to role
 */
export async function grantPermissions(
  roleId: RoleId,
  permissionIds: PermissionId[]
): Promise<void> {
  return getRoleManager().grantPermissions(roleId, permissionIds);
}

/**
 * Revoke permission from role
 */
export async function revokePermission(
  roleId: RoleId,
  permissionId: PermissionId
): Promise<void> {
  return getRoleManager().revokePermission(roleId, permissionId);
}

/**
 * Get all permissions for a role (including inherited)
 */
export async function getRolePermissions(
  roleId: RoleId,
  options?: RoleOptions
): Promise<Set<PermissionId>> {
  return getRoleManager().getRolePermissions(roleId, options);
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
  return getRoleManager().assignRole(userId, roleId, options);
}

/**
 * Remove role from user
 */
export async function removeRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<void> {
  return getRoleManager().removeRole(userId, roleId, scope);
}

/**
 * Check if user has specific role
 */
export async function hasRole(
  userId: UserId,
  roleId: RoleId,
  scope?: string
): Promise<boolean> {
  return getRoleManager().hasRole(userId, roleId, scope);
}

/**
 * Check if user has any of the specified roles
 */
export async function hasAnyRole(
  userId: UserId,
  roleIds: RoleId[],
  scope?: string
): Promise<boolean> {
  return getRoleManager().hasAnyRole(userId, roleIds, scope);
}

/**
 * Check if user has all specified roles
 */
export async function hasAllRoles(
  userId: UserId,
  roleIds: RoleId[],
  scope?: string
): Promise<boolean> {
  return getRoleManager().hasAllRoles(userId, roleIds, scope);
}

/**
 * Get all role assignments for a user
 */
export async function getUserRoles(userId: UserId): Promise<UserRole[]> {
  return getRoleManager().getUserRoles(userId);
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
  return getGuards().hasPermission(userId, permissionId, options);
}

/**
 * Check if user has any of the specified permissions
 */
export async function hasAnyPermission(
  userId: UserId,
  permissionIds: PermissionId[],
  options?: PermissionCheckOptions
): Promise<boolean> {
  const guards = getGuards();

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
  const guards = getGuards();

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
  const context = {
    userId,
    ...(options?.scope !== undefined && { scope: options.scope }),
  };

  // Create a throwing guards instance for requirePermission
  const guards = new RBACGuards({ roleManager: getRoleManager() });
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
  const context = {
    userId,
    ...(scope !== undefined && { scope }),
  };

  // Create a throwing guards instance for requireRole
  const guards = new RBACGuards({ roleManager: getRoleManager() });
  await guards.requireRole(context, roleId);
}
