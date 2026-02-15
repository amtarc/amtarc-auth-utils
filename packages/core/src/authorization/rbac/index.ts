/**
 * RBAC (Role-Based Access Control) Module
 * Provides role and permission management with hierarchy support
 *
 * @module @auth-utils/core/authorization/rbac
 */

export * from './types';
export * from './storage';
export * from './permission-manager';
export * from './role-manager';
export * from './role-hierarchy';
export * from './rbac-guards';

// Functional API (recommended for most users)
export * from './rbac-manager';

// Convenience exports for class-based usage
export { MemoryRBACStorage } from './storage';

export { PermissionManager } from './permission-manager';

export { RoleManager } from './role-manager';

export { RoleHierarchy } from './role-hierarchy';

export { RBACGuards, createRBACGuards } from './rbac-guards';
