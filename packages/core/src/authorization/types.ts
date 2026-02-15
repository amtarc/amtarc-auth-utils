/**
 * Shared authorization types across all modules
 */

/**
 * Generic user identifier
 */
export type UserId = string | number;

/**
 * Generic resource identifier
 */
export type ResourceId = string | number;

/**
 * Common authorization result
 */
export interface AuthorizationResult {
  /** Whether access is granted */
  granted: boolean;
  /** Reason for decision (for debugging/audit) */
  reason?: string;
  /** Additional context about the decision */
  context?: Record<string, unknown>;
}

/**
 * Authorization context passed to evaluators
 */
export interface AuthorizationContext {
  /** Current user */
  user: {
    id: UserId;
    [key: string]: unknown;
  };
  /** Resource being accessed (optional) */
  resource?: {
    id: ResourceId;
    type: string;
    [key: string]: unknown;
  };
  /** Action being performed */
  action?: string;
  /** Environment attributes */
  environment?: {
    timestamp: number;
    ip?: string;
    userAgent?: string;
    [key: string]: unknown;
  };
  /** Custom attributes */
  [key: string]: unknown;
}

/**
 * Base error class for authorization errors
 */
export class AuthorizationError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly context?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

/**
 * Error thrown when user lacks required role
 */
export class InsufficientRoleError extends AuthorizationError {
  constructor(required: string | string[], context?: Record<string, unknown>) {
    super(
      `Missing required role(s): ${Array.isArray(required) ? required.join(', ') : required}`,
      'INSUFFICIENT_ROLE',
      context
    );
    this.name = 'InsufficientRoleError';
  }
}

/**
 * Error thrown when user lacks required permission
 */
export class InsufficientPermissionError extends AuthorizationError {
  constructor(required: string | string[], context?: Record<string, unknown>) {
    super(
      `Missing required permission(s): ${Array.isArray(required) ? required.join(', ') : required}`,
      'INSUFFICIENT_PERMISSION',
      context
    );
    this.name = 'InsufficientPermissionError';
  }
}

/**
 * Error thrown when access to resource is denied
 */
export class ResourceAccessDeniedError extends AuthorizationError {
  constructor(
    resourceId: ResourceId,
    action: string,
    context?: Record<string, unknown>
  ) {
    super(
      `Access denied to resource ${resourceId} for action ${action}`,
      'RESOURCE_ACCESS_DENIED',
      context
    );
    this.name = 'ResourceAccessDeniedError';
  }
}

/**
 * Error thrown when a role is not found
 */
export class RoleNotFoundError extends AuthorizationError {
  constructor(roleId: string, context?: Record<string, unknown>) {
    super(`Role not found: ${roleId}`, 'ROLE_NOT_FOUND', context);
    this.name = 'RoleNotFoundError';
  }
}

/**
 * Error thrown when a permission is not found
 */
export class PermissionNotFoundError extends AuthorizationError {
  constructor(permissionId: string, context?: Record<string, unknown>) {
    super(
      `Permission not found: ${permissionId}`,
      'PERMISSION_NOT_FOUND',
      context
    );
    this.name = 'PermissionNotFoundError';
  }
}

/**
 * Error thrown when attempting to create a role that already exists
 */
export class RoleExistsError extends AuthorizationError {
  constructor(roleId: string, context?: Record<string, unknown>) {
    super(`Role already exists: ${roleId}`, 'ROLE_EXISTS', context);
    this.name = 'RoleExistsError';
  }
}

/**
 * Error thrown when attempting to create a permission that already exists
 */
export class PermissionExistsError extends AuthorizationError {
  constructor(permissionId: string, context?: Record<string, unknown>) {
    super(
      `Permission already exists: ${permissionId}`,
      'PERMISSION_EXISTS',
      context
    );
    this.name = 'PermissionExistsError';
  }
}
