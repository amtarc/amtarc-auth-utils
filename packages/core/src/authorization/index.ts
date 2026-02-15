/**
 * Authorization Package
 * Comprehensive authorization utilities including RBAC, ABAC, and resource-based access control
 *
 * @module @auth-utils/core/authorization
 */

// Export types (but not error classes to avoid conflicts with ./errors module)
export type {
  UserId,
  ResourceId,
  AuthorizationResult,
  AuthorizationContext,
} from './types';

// Export RBAC module (includes functional API)
export * from './rbac';

// Note: Authorization error classes (AuthorizationError, InsufficientRoleError, etc.)
// are available in ./authorization/types but not re-exported here to avoid conflicts
// with the main ./errors module. Import directly from '@amtarc/auth-utils/authorization/types'
// if you need these specific error classes for RBAC/authorization.

// Convenience exports for class-based RBAC
export {
  MemoryRBACStorage,
  PermissionManager,
  RoleManager,
  RoleHierarchy,
  RBACGuards,
  createRBACGuards,
} from './rbac';

// Functional API exports (recommended - matches session/security patterns)
export {
  setDefaultRBACStorage,
  definePermission,
  definePermissions,
  updatePermission,
  deletePermission,
  getPermission,
  listPermissions,
  defineRole,
  updateRole,
  deleteRole,
  getRole,
  listRoles,
  grantPermission,
  grantPermissions,
  revokePermission,
  getRolePermissions,
  assignRole,
  removeRole,
  hasRole,
  hasAnyRole,
  hasAllRoles,
  getUserRoles,
  hasPermission,
  hasAnyPermission,
  hasAllPermissions,
  requirePermission,
  requireRole,
} from './rbac';

export type {
  RoleId,
  PermissionId,
  Role,
  Permission,
  UserRole,
  RBACStorageAdapter,
  RoleOptions,
  PermissionCheckOptions,
  HierarchyValidation,
} from './rbac';
