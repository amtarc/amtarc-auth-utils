/**
 * Resource-Based Access Control types
 * Provides fine-grained resource permissions and ownership patterns
 */

import type { UserId, ResourceId, AuthorizationResult } from '../types';

/**
 * Resource action types
 */
export type ResourceAction =
  | 'create'
  | 'read'
  | 'update'
  | 'delete'
  | 'admin'
  | string;

/**
 * Resource type
 */
export interface Resource {
  /** Resource identifier */
  id: ResourceId;
  /** Resource type (e.g., 'document', 'project', 'user') */
  type: string;
  /** Resource owner */
  ownerId?: UserId;
  /** Team that owns the resource */
  teamId?: string;
  /** Organization that owns the resource */
  organizationId?: string;
  /** Resource attributes */
  attributes?: Record<string, unknown>;
  /** Creation timestamp */
  createdAt?: number;
  /** Last update timestamp */
  updatedAt?: number;
}

/**
 * Resource permission entry
 */
export interface ResourcePermission {
  /** User ID */
  userId?: UserId;
  /** Team ID (for team-based permissions) */
  teamId?: string;
  /** Role ID (for role-based permissions) */
  roleId?: string;
  /** Resource ID */
  resourceId: ResourceId;
  /** Resource type */
  resourceType: string;
  /** Allowed actions */
  actions: Set<ResourceAction>;
  /** Permission scope */
  scope?: 'own' | 'team' | 'organization' | 'all';
  /** Granted timestamp */
  grantedAt: number;
  /** Optional expiration */
  expiresAt?: number;
  /** Granted by (for audit) */
  grantedBy?: UserId;
  /** Permission metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Ownership rule
 */
export interface OwnershipRule {
  /** Rule identifier */
  id: string;
  /** Resource type this rule applies to */ resourceType: string;
  /** Ownership type */
  type: 'owner' | 'team' | 'organization' | 'custom';
  /** Actions automatically granted to owner */
  defaultActions?: ResourceAction[];
  /** Custom ownership validator */
  validator?: (context: {
    userId: UserId;
    resource: Resource;
    action: ResourceAction;
  }) => Promise<boolean> | boolean;
}

/**
 * Resource access check result
 */
export interface ResourceAccessResult extends AuthorizationResult {
  /** Access level granted */
  accessLevel?: 'none' | 'read' | 'write' | 'admin';
  /** Reason for access decision */
  reason: string;
  /** Ownership status */
  isOwner?: boolean;
  /** Team member status */
  isTeamMember?: boolean;
}

/**
 * Resource storage adapter
 */
export interface ResourceStorageAdapter {
  /** Get resource by ID */
  getResource(id: ResourceId): Promise<Resource | null>;
  /** Save resource */
  saveResource(resource: Resource): Promise<void>;
  /** Delete resource */
  deleteResource(id: ResourceId): Promise<void>;
  /** List resources */
  listResources(filter?: {
    type?: string;
    ownerId?: UserId;
    teamId?: string;
    organizationId?: string;
  }): Promise<Resource[]>;

  /** Get resource permission */
  getResourcePermission(
    userId: UserId,
    resourceId: ResourceId
  ): Promise<ResourcePermission | null>;
  /** Save resource permission */
  saveResourcePermission(permission: ResourcePermission): Promise<void>;
  /** Delete resource permission */
  deleteResourcePermission(
    userId: UserId,
    resourceId: ResourceId
  ): Promise<void>;
  /** List user's resource permissions */
  listUserResourcePermissions(userId: UserId): Promise<ResourcePermission[]>;
  /** List permissions for a resource */
  listResourcePermissions(
    resourceId: ResourceId
  ): Promise<ResourcePermission[]>;
}

/**
 * Resource access options
 */
export interface ResourceAccessOptions {
  /** Check ownership */
  checkOwnership?: boolean;
  /** Check team membership */
  checkTeam?: boolean;
  /** Check organization membership */
  checkOrganization?: boolean;
  /** Include inherited permissions */
  includeInherited?: boolean;
  /** Additional context for custom validators */
  context?: Record<string, unknown>;
}
