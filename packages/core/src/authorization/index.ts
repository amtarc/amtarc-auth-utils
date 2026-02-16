/**
 * Authorization Package
 * Comprehensive authorization utilities including RBAC, ABAC, and resource-based access control
 *
 * @module @auth-utils/core/authorization
 */

// ============================================================================
// Core Types
// ============================================================================

export type {
  UserId,
  ResourceId,
  AuthorizationResult,
  AuthorizationContext,
} from './types';

// Note: RBAC error classes (RBACAuthorizationError, InsufficientRoleError, etc.)
// are available in ./authorization/types but not re-exported here to avoid conflicts
// with the main ./errors module. Import directly from '@amtarc/auth-utils/authorization/types'
// if you need these specific error classes for RBAC/authorization.

// ============================================================================
// RBAC (Role-Based Access Control)
// ============================================================================

// Export RBAC module
export * from './rbac';

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
  requirePermission as requireRBACPermission,
  requireRole as requireRBACRole,
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

// ============================================================================
// ABAC (Attribute-Based Access Control)
// ============================================================================

export {
  PolicyEngine,
  createPolicyEngine,
  evaluateComparison,
  evaluateRule,
  evaluateRuleGroup,
  evaluateRules,
  getAttributeValue,
  countRules,
  UserAttributeProvider,
  ResourceAttributeProvider,
  EnvironmentAttributeProvider,
  CustomAttributeProvider,
  createAttributeProvider,
  MemoryPolicyStorage,
} from './abac';

export type {
  Policy,
  PolicyContext,
  PolicyEvaluationResult,
  PolicyEvaluationOptions,
  PolicyStorageAdapter,
  PolicyCacheEntry,
  Rule,
  RuleGroup,
  AttributeValue,
  Attributes,
  ComparisonOperator,
  LogicalOperator,
  AttributeProvider,
} from './abac';

// ============================================================================
// Resource-Based Access Control
// ============================================================================

export {
  ResourceManager,
  MemoryResourceStorage,
  createOwnerFullAccessRule,
  createOwnerReadWriteRule,
  createOwnerReadOnlyRule,
  createTeamOwnershipRule,
  createOrganizationOwnershipRule,
  createCustomOwnershipRule,
  ResourceActions,
  ActionGroups,
} from './resource';

export type {
  Resource,
  ResourcePermission,
  ResourceAction,
  ResourceAccessResult,
  ResourceAccessOptions,
  ResourceStorageAdapter,
  OwnershipRule,
} from './resource';

// ============================================================================
// Authorization Guards
// ============================================================================

export {
  requirePermission,
  requireRole,
  requirePolicy,
  requireResourceAccess,
  requireOwnership,
  combineGuardsAnd,
  combineGuardsOr,
  createCustomGuard,
} from './guards';

// Note: Guard types (GuardContext, GuardResult, GuardFunction) are
// not re-exported from the main index to avoid conflicts with ./guards module.
// Import them directly from '@amtarc/auth-utils/authorization/guards' if needed.
