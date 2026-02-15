/**
 * RBAC-specific types and interfaces
 * Re-exports storage types for convenience
 */

export type {
  RoleId,
  PermissionId,
  Role,
  Permission,
  UserRole,
  RBACStorageAdapter,
} from './storage/storage-adapter';

/**
 * Options for role operations
 */
export interface RoleOptions {
  /** Include inherited permissions */
  includeInherited?: boolean;
  /** Maximum depth for role hierarchy traversal */
  maxDepth?: number;
}

/**
 * Options for permission checks
 */
export interface PermissionCheckOptions {
  /** Require ALL permissions (AND) vs ANY permission (OR) */
  mode?: 'AND' | 'OR';
  /** Include inherited permissions */
  includeInherited?: boolean;
  /** Role assignment scope to check */
  scope?: string;
}

/**
 * Role hierarchy validation result
 */
export interface HierarchyValidation {
  valid: boolean;
  errors?: string[];
  warnings?: string[];
}
