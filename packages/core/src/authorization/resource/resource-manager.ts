/**
 * Resource manager
 * Manages resource permissions and access control
 */

import type {
  Resource,
  ResourcePermission,
  ResourceAction,
  ResourceAccessResult,
  ResourceAccessOptions,
  ResourceStorageAdapter,
  OwnershipRule,
} from './types';
import type { UserId, ResourceId } from '../types';

export interface ResourceManagerOptions {
  storage: ResourceStorageAdapter;
  ownershipRules?: OwnershipRule[];
}

export class ResourceManager {
  private ownershipRules = new Map<string, OwnershipRule>();

  constructor(private options: ResourceManagerOptions) {
    // Register ownership rules
    options.ownershipRules?.forEach((rule) => {
      this.ownershipRules.set(rule.resourceType, rule);
    });
  }

  /**
   * Register an ownership rule
   */
  registerOwnershipRule(rule: OwnershipRule): void {
    this.ownershipRules.set(rule.resourceType, rule);
  }

  /**
   * Grant access to a resource
   */
  async grantAccess(
    userId: UserId,
    resourceId: ResourceId,
    resourceType: string,
    actions: ResourceAction | ResourceAction[],
    options?: {
      scope?: 'own' | 'team' | 'organization' | 'all';
      expiresAt?: number;
      grantedBy?: UserId;
      metadata?: Record<string, unknown>;
    }
  ): Promise<void> {
    const permission: ResourcePermission = {
      userId,
      resourceId,
      resourceType,
      actions: new Set(Array.isArray(actions) ? actions : [actions]),
      grantedAt: Date.now(),
    };

    // Add optional properties only if they have values
    if (options?.scope) permission.scope = options.scope;
    if (options?.expiresAt) permission.expiresAt = options.expiresAt;
    if (options?.grantedBy) permission.grantedBy = options.grantedBy;
    if (options?.metadata) permission.metadata = options.metadata;

    await this.options.storage.saveResourcePermission(permission);
  }

  /**
   * Revoke access to a resource
   */
  async revokeAccess(userId: UserId, resourceId: ResourceId): Promise<void> {
    await this.options.storage.deleteResourcePermission(userId, resourceId);
  }

  /**
   * Check if user can access resource for a specific action
   */
  async canAccess(
    userId: UserId,
    resourceId: ResourceId,
    action: ResourceAction,
    options: ResourceAccessOptions = {}
  ): Promise<ResourceAccessResult> {
    // Get resource
    const resource = await this.options.storage.getResource(resourceId);
    if (!resource) {
      return {
        granted: false,
        reason: 'Resource not found',
      };
    }

    // Check ownership if enabled
    if (options.checkOwnership !== false) {
      const ownershipResult = await this.checkOwnership(
        userId,
        resource,
        action
      );
      if (ownershipResult.granted) {
        return ownershipResult;
      }
    }

    // Check explicit permissions
    const permission = await this.options.storage.getResourcePermission(
      userId,
      resourceId
    );
    if (permission) {
      // Check expiration
      if (permission.expiresAt && permission.expiresAt < Date.now()) {
        return {
          granted: false,
          reason: 'Permission expired',
        };
      }

      // Check if action is allowed
      if (permission.actions.has(action) || permission.actions.has('admin')) {
        return {
          granted: true,
          reason: 'Explicit permission granted',
          accessLevel: permission.actions.has('admin') ? 'admin' : 'write',
        };
      }
    }

    // No access granted
    return {
      granted: false,
      reason: 'No permission found for this action',
    };
  }

  /**
   * Check ownership-based access
   */
  private async checkOwnership(
    userId: UserId,
    resource: Resource,
    action: ResourceAction
  ): Promise<ResourceAccessResult> {
    const rule = this.ownershipRules.get(resource.type);

    // Check if user is the owner
    const isOwner = resource.ownerId === userId;

    if (isOwner) {
      // Check if action is in default actions
      if (rule?.defaultActions?.includes(action)) {
        return {
          granted: true,
          reason: 'Owner has default access',
          isOwner: true,
          accessLevel: 'admin',
        };
      }
    }

    // Use custom validator if available
    if (rule?.validator) {
      const granted = await rule.validator({ userId, resource, action });
      if (granted) {
        return {
          granted: true,
          reason: 'Custom ownership rule granted access',
          isOwner,
        };
      }
    }

    return {
      granted: false,
      reason: 'No ownership access',
      isOwner,
    };
  }

  /**
   * List all resources the user can access with a specific action
   */
  async listUserResources(
    userId: UserId,
    action: ResourceAction,
    options?: {
      resourceType?: string;
    }
  ): Promise<Resource[]> {
    // Get user's permissions
    const permissions =
      await this.options.storage.listUserResourcePermissions(userId);

    // Filter permissions that include the action
    const resourceIds = permissions
      .filter((p) => p.actions.has(action) || p.actions.has('admin'))
      .filter(
        (p) => !options?.resourceType || p.resourceType === options.resourceType
      )
      .map((p) => p.resourceId);

    // Get resources (in a real implementation, this would be optimized)
    const resources: Resource[] = [];
    for (const id of resourceIds) {
      const resource = await this.options.storage.getResource(id);
      if (resource) {
        resources.push(resource);
      }
    }

    // Also include owned resources
    const filters: { type?: string; ownerId?: UserId } = { ownerId: userId };
    if (options?.resourceType) filters.type = options.resourceType;
    const ownedResources = await this.options.storage.listResources(filters);

    // Merge and deduplicate
    const allResourcesMap = new Map<ResourceId, Resource>();
    [...resources, ...ownedResources].forEach((r) => {
      allResourcesMap.set(r.id, r);
    });

    return Array.from(allResourcesMap.values());
  }

  /**
   * List all users who can access a specific resource
   */
  async listResourceUsers(resourceId: ResourceId): Promise<UserId[]> {
    const permissions =
      await this.options.storage.listResourcePermissions(resourceId);
    return permissions
      .filter((p) => p.userId !== undefined)
      .map((p) => p.userId as UserId);
  }

  /**
   * Transfer resource ownership
   */
  async transferOwnership(
    resourceId: ResourceId,
    newOwnerId: UserId
  ): Promise<void> {
    const resource = await this.options.storage.getResource(resourceId);
    if (!resource) {
      throw new Error(`Resource ${resourceId} not found`);
    }

    resource.ownerId = newOwnerId;
    resource.updatedAt = Date.now();

    await this.options.storage.saveResource(resource);
  }

  /**
   * Create a new resource with owner
   */
  async createResource(
    resource: Omit<Resource, 'createdAt' | 'updatedAt'>
  ): Promise<Resource> {
    const now = Date.now();
    const newResource: Resource = {
      ...resource,
      createdAt: now,
      updatedAt: now,
    };

    await this.options.storage.saveResource(newResource);
    return newResource;
  }

  /**
   * Delete a resource and all its permissions
   */
  async deleteResource(resourceId: ResourceId): Promise<void> {
    // Delete all permissions for this resource
    const permissions =
      await this.options.storage.listResourcePermissions(resourceId);
    for (const permission of permissions) {
      if (permission.userId) {
        await this.options.storage.deleteResourcePermission(
          permission.userId,
          resourceId
        );
      }
    }

    // Delete the resource
    await this.options.storage.deleteResource(resourceId);
  }
}
