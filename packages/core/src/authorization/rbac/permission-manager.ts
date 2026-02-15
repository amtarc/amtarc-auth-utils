/**
 * Permission management utilities
 * Handles permission definition and querying
 */

import type { Permission, PermissionId, RBACStorageAdapter } from './types';
import { PermissionExistsError, PermissionNotFoundError } from '../types';

export interface PermissionManagerOptions {
  storage: RBACStorageAdapter;
}

export class PermissionManager {
  constructor(private options: PermissionManagerOptions) {}

  /**
   * Define a new permission
   */
  async definePermission(
    permission: Omit<Permission, 'id'> & { id?: PermissionId }
  ): Promise<Permission> {
    // Generate ID from name if not provided
    const id = permission.id || this.generatePermissionId(permission.name);

    // Check if permission already exists
    const existing = await this.options.storage.getPermission(id);
    if (existing) {
      throw new PermissionExistsError(id);
    }

    const newPermission: Permission = {
      id,
      name: permission.name,
      ...(permission.description !== undefined && {
        description: permission.description,
      }),
      ...(permission.resourceType !== undefined && {
        resourceType: permission.resourceType,
      }),
      ...(permission.actions !== undefined && { actions: permission.actions }),
      ...(permission.metadata !== undefined && {
        metadata: permission.metadata,
      }),
    };

    await this.options.storage.savePermission(newPermission);
    return newPermission;
  }

  /**
   * Update existing permission
   */
  async updatePermission(
    id: PermissionId,
    updates: Partial<Omit<Permission, 'id'>>
  ): Promise<Permission> {
    const existing = await this.options.storage.getPermission(id);
    if (!existing) {
      throw new PermissionNotFoundError(id);
    }

    const updated: Permission = {
      ...existing,
      ...updates,
      id, // Ensure ID doesn't change
    };

    await this.options.storage.savePermission(updated);
    return updated;
  }

  /**
   * Delete a permission
   */
  async deletePermission(id: PermissionId): Promise<void> {
    const existing = await this.options.storage.getPermission(id);
    if (!existing) {
      throw new PermissionNotFoundError(id);
    }

    await this.options.storage.deletePermission(id);
  }

  /**
   * Get permission by ID
   */
  async getPermission(id: PermissionId): Promise<Permission | null> {
    return this.options.storage.getPermission(id);
  }

  /**
   * List all permissions
   */
  async listPermissions(): Promise<Permission[]> {
    return this.options.storage.listPermissions();
  }

  /**
   * List permissions for a specific resource type
   */
  async listPermissionsByResourceType(
    resourceType: string
  ): Promise<Permission[]> {
    const allPermissions = await this.options.storage.listPermissions();
    return allPermissions.filter((p) => p.resourceType === resourceType);
  }

  /**
   * Batch define permissions
   */
  async definePermissions(
    permissions: Array<Omit<Permission, 'id'> & { id?: PermissionId }>
  ): Promise<Permission[]> {
    const results: Permission[] = [];

    for (const permission of permissions) {
      try {
        const created = await this.definePermission(permission);
        results.push(created);
      } catch (error) {
        // Continue with other permissions even if one fails
        console.warn(`Failed to define permission: ${error}`);
      }
    }

    return results;
  }

  /**
   * Generate permission ID from name
   * Converts "Read Users" -> "read:users"
   */
  private generatePermissionId(name: string): PermissionId {
    return name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, ':')
      .replace(/^:+/, '')
      .replace(/:+$/, '');
  }
}
