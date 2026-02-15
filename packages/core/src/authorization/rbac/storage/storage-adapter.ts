/**
 * RBAC storage adapter interface
 * Defines the contract for RBAC storage implementations
 */

import type { UserId } from '../../types';

/**
 * Role identifier
 */
export type RoleId = string;

/**
 * Permission identifier
 */
export type PermissionId = string;

/**
 * Role definition
 */
export interface Role {
  /** Unique role identifier */
  id: RoleId;
  /** Human-readable role name */
  name: string;
  /** Role description */
  description?: string;
  /** Direct permissions granted to this role */
  permissions: Set<PermissionId>;
  /** Parent role IDs (for inheritance) */
  parents?: Set<RoleId>;
  /** Metadata for custom use */
  metadata?: Record<string, unknown>;
  /** Creation timestamp */
  createdAt?: number;
  /** Last update timestamp */
  updatedAt?: number;
}

/**
 * Permission definition
 */
export interface Permission {
  /** Unique permission identifier */
  id: PermissionId;
  /** Human-readable name */
  name: string;
  /** Permission description */
  description?: string;
  /** Resource type this permission applies to */
  resourceType?: string;
  /** Actions this permission allows */
  actions?: string[];
  /** Metadata for custom use */
  metadata?: Record<string, unknown>;
}

/**
 * User-role assignment
 */
export interface UserRole {
  /** User ID */
  userId: UserId;
  /** Role ID */
  roleId: RoleId;
  /** Assignment timestamp */
  assignedAt: number;
  /** Optional expiration timestamp */
  expiresAt?: number;
  /** Assignment scope (e.g., organization, team) */
  scope?: string;
  /** Assignment metadata */
  metadata?: Record<string, unknown>;
}

/**
 * RBAC storage adapter interface
 * Following the same pattern as SessionStorageAdapter
 */
export interface RBACStorageAdapter {
  // Role operations
  getRole(roleId: RoleId): Promise<Role | null>;
  saveRole(role: Role): Promise<void>;
  deleteRole(roleId: RoleId): Promise<void>;
  listRoles(): Promise<Role[]>;

  // Permission operations
  getPermission(permissionId: PermissionId): Promise<Permission | null>;
  savePermission(permission: Permission): Promise<void>;
  deletePermission(permissionId: PermissionId): Promise<void>;
  listPermissions(): Promise<Permission[]>;

  // User-role assignments
  getUserRoles(userId: UserId): Promise<UserRole[]>;
  assignUserRole(assignment: UserRole): Promise<void>;
  removeUserRole(userId: UserId, roleId: RoleId, scope?: string): Promise<void>;
  listUsersByRole(roleId: RoleId): Promise<UserId[]>;
}
