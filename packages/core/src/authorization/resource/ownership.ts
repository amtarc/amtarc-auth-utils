/**
 * Common ownership patterns
 * Pre-built ownership rules for common scenarios
 */

import type { OwnershipRule } from './types';

/**
 * Owner has full access (all actions)
 */
export function createOwnerFullAccessRule(resourceType: string): OwnershipRule {
  return {
    id: `${resourceType}-owner-full`,
    resourceType,
    type: 'owner',
    defaultActions: ['create', 'read', 'update', 'delete', 'admin'],
  };
}

/**
 * Owner has read and update access only
 */
export function createOwnerReadWriteRule(resourceType: string): OwnershipRule {
  return {
    id: `${resourceType}-owner-rw`,
    resourceType,
    type: 'owner',
    defaultActions: ['read', 'update'],
  };
}

/**
 * Owner has read-only access
 */
export function createOwnerReadOnlyRule(resourceType: string): OwnershipRule {
  return {
    id: `${resourceType}-owner-ro`,
    resourceType,
    type: 'owner',
    defaultActions: ['read'],
  };
}

/**
 * Team-based ownership rule
 * Users in the same team can access the resource
 */
export function createTeamOwnershipRule(
  resourceType: string,
  teamActions: string[] = ['read']
): OwnershipRule {
  return {
    id: `${resourceType}-team`,
    resourceType,
    type: 'team',
    defaultActions: teamActions,
    validator: async ({ userId: _userId, resource }) => {
      // This would typically check if user is in the same team
      // Placeholder implementation
      return resource.teamId !== undefined;
    },
  };
}

/**
 * Organization-based ownership rule
 * Users in the same organization can access the resource
 */
export function createOrganizationOwnershipRule(
  resourceType: string,
  orgActions: string[] = ['read']
): OwnershipRule {
  return {
    id: `${resourceType}-org`,
    resourceType,
    type: 'organization',
    defaultActions: orgActions,
    validator: async ({ userId: _userId, resource }) => {
      // This would typically check if user is in the same organization
      // Placeholder implementation
      return resource.organizationId !== undefined;
    },
  };
}

/**
 * Custom ownership rule with validator
 */
export function createCustomOwnershipRule(
  id: string,
  resourceType: string,
  validator: OwnershipRule['validator'],
  defaultActions?: string[]
): OwnershipRule {
  const rule: OwnershipRule = {
    id,
    resourceType,
    type: 'custom',
  };

  // Add optional properties only if they have values
  if (defaultActions) rule.defaultActions = defaultActions;
  if (validator) rule.validator = validator;

  return rule;
}

/**
 * Common resource actions
 */
export const ResourceActions = {
  /** Create new resources */
  CREATE: 'create' as const,
  /** Read/view resources */
  READ: 'read' as const,
  /** Update existing resources */
  UPDATE: 'update' as const,
  /** Delete resources */
  DELETE: 'delete' as const,
  /** Full administrative access */
  ADMIN: 'admin' as const,
  /** Share resources with others */
  SHARE: 'share' as const,
  /** Comment on resources */
  COMMENT: 'comment' as const,
  /** Download resources */
  DOWNLOAD: 'download' as const,
  /** Execute/run resources */
  EXECUTE: 'execute' as const,
};

/**
 * Common action groups
 */
export const ActionGroups = {
  /** Read-only actions */
  READ_ONLY: ['read'] as const,
  /** Read and write actions */
  READ_WRITE: ['read', 'update'] as const,
  /** CRUD actions */
  CRUD: ['create', 'read', 'update', 'delete'] as const,
  /** Full access */
  FULL: ['create', 'read', 'update', 'delete', 'admin'] as const,
};
