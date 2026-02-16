/**
 * In-memory resource storage adapter
 * For development and testing
 */

import type {
  Resource,
  ResourcePermission,
  ResourceStorageAdapter,
} from '../types';
import type { UserId, ResourceId } from '../../types';

export class MemoryResourceStorage implements ResourceStorageAdapter {
  private resources = new Map<ResourceId, Resource>();
  private permissions = new Map<string, ResourcePermission>();

  async getResource(id: ResourceId): Promise<Resource | null> {
    return this.resources.get(id) || null;
  }

  async saveResource(resource: Resource): Promise<void> {
    this.resources.set(resource.id, { ...resource });
  }

  async deleteResource(id: ResourceId): Promise<void> {
    this.resources.delete(id);
  }

  async listResources(filter?: {
    type?: string;
    ownerId?: UserId;
    teamId?: string;
    organizationId?: string;
  }): Promise<Resource[]> {
    let resources = Array.from(this.resources.values());

    if (filter?.type) {
      resources = resources.filter((r) => r.type === filter.type);
    }

    if (filter?.ownerId !== undefined) {
      resources = resources.filter((r) => r.ownerId === filter.ownerId);
    }

    if (filter?.teamId) {
      resources = resources.filter((r) => r.teamId === filter.teamId);
    }

    if (filter?.organizationId) {
      resources = resources.filter(
        (r) => r.organizationId === filter.organizationId
      );
    }

    return resources;
  }

  async getResourcePermission(
    userId: UserId,
    resourceId: ResourceId
  ): Promise<ResourcePermission | null> {
    const key = this.getPermissionKey(userId, resourceId);
    return this.permissions.get(key) || null;
  }

  async saveResourcePermission(permission: ResourcePermission): Promise<void> {
    if (!permission.userId) {
      throw new Error('Permission must have userId');
    }
    const key = this.getPermissionKey(permission.userId, permission.resourceId);
    this.permissions.set(key, {
      ...permission,
      actions: new Set(permission.actions),
    });
  }

  async deleteResourcePermission(
    userId: UserId,
    resourceId: ResourceId
  ): Promise<void> {
    const key = this.getPermissionKey(userId, resourceId);
    this.permissions.delete(key);
  }

  async listUserResourcePermissions(
    userId: UserId
  ): Promise<ResourcePermission[]> {
    return Array.from(this.permissions.values()).filter(
      (p) => p.userId === userId
    );
  }

  async listResourcePermissions(
    resourceId: ResourceId
  ): Promise<ResourcePermission[]> {
    return Array.from(this.permissions.values()).filter(
      (p) => p.resourceId === resourceId
    );
  }

  private getPermissionKey(userId: UserId, resourceId: ResourceId): string {
    return `${userId}:${resourceId}`;
  }

  /**
   * Clear all data (useful for testing)
   */
  clear(): void {
    this.resources.clear();
    this.permissions.clear();
  }
}
