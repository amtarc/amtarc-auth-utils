/**
 * Role hierarchy validation utilities
 * Ensures role hierarchies are valid and prevent circular dependencies
 */

import type {
  Role,
  RoleId,
  HierarchyValidation,
  RBACStorageAdapter,
} from './types';

export interface RoleHierarchyOptions {
  storage: RBACStorageAdapter;
  /** Maximum allowed hierarchy depth */
  maxDepth?: number;
}

export class RoleHierarchy {
  private maxDepth: number;

  constructor(private options: RoleHierarchyOptions) {
    this.maxDepth = options.maxDepth || 10;
  }

  /**
   * Validate role hierarchy for circular dependencies
   */
  async validateHierarchy(roleId: RoleId): Promise<HierarchyValidation> {
    const errors: string[] = [];
    const warnings: string[] = [];

    const role = await this.options.storage.getRole(roleId);
    if (!role) {
      return {
        valid: false,
        errors: [`Role ${roleId} not found`],
      };
    }

    // Check for circular dependencies
    const visited = new Set<RoleId>();
    const hasCircular = await this.detectCircular(role, visited, [roleId]);

    if (hasCircular) {
      errors.push(
        `Circular dependency detected in role hierarchy for ${roleId}`
      );
    }

    // Check hierarchy depth
    const depth = await this.calculateDepth(roleId);
    if (depth > this.maxDepth) {
      errors.push(
        `Role hierarchy depth (${depth}) exceeds maximum allowed depth (${this.maxDepth})`
      );
    } else if (depth > this.maxDepth * 0.8) {
      warnings.push(
        `Role hierarchy depth (${depth}) is approaching maximum (${this.maxDepth})`
      );
    }

    // Check for orphaned parents
    if (role.parents) {
      for (const parentId of role.parents) {
        const parent = await this.options.storage.getRole(parentId);
        if (!parent) {
          errors.push(`Parent role ${parentId} does not exist`);
        }
      }
    }

    return {
      valid: errors.length === 0,
      ...(errors.length > 0 && { errors }),
      ...(warnings.length > 0 && { warnings }),
    };
  }

  /**
   * Validate entire role hierarchy system
   */
  async validateAll(): Promise<HierarchyValidation> {
    const allRoles = await this.options.storage.listRoles();
    const errors: string[] = [];
    const warnings: string[] = [];

    for (const role of allRoles) {
      const validation = await this.validateHierarchy(role.id);
      if (!validation.valid) {
        if (validation.errors) {
          errors.push(...validation.errors);
        }
      }
      if (validation.warnings) {
        warnings.push(...validation.warnings);
      }
    }

    const result: HierarchyValidation = { valid: errors.length === 0 };
    if (errors.length > 0) result.errors = errors;
    if (warnings.length > 0) result.warnings = warnings;
    return result;
  }

  /**
   * Calculate the depth of a role in the hierarchy
   */
  async calculateDepth(
    roleId: RoleId,
    visited = new Set<RoleId>()
  ): Promise<number> {
    if (visited.has(roleId)) {
      return 0; // Circular dependency, return 0
    }

    visited.add(roleId);
    const role = await this.options.storage.getRole(roleId);

    if (!role || !role.parents || role.parents.size === 0) {
      return 1;
    }

    let maxParentDepth = 0;
    for (const parentId of role.parents) {
      const parentDepth = await this.calculateDepth(parentId, new Set(visited));
      maxParentDepth = Math.max(maxParentDepth, parentDepth);
    }

    return maxParentDepth + 1;
  }

  /**
   * Get all ancestor roles (parents, grandparents, etc.)
   */
  async getAncestors(roleId: RoleId): Promise<Set<RoleId>> {
    const ancestors = new Set<RoleId>();
    await this.collectAncestors(roleId, ancestors, new Set());
    return ancestors;
  }

  /**
   * Get all descendant roles (children, grandchildren, etc.)
   */
  async getDescendants(roleId: RoleId): Promise<Set<RoleId>> {
    const descendants = new Set<RoleId>();
    const allRoles = await this.options.storage.listRoles();

    for (const role of allRoles) {
      const ancestors = await this.getAncestors(role.id);
      if (ancestors.has(roleId)) {
        descendants.add(role.id);
      }
    }

    return descendants;
  }

  /**
   * Check if roleA is an ancestor of roleB
   */
  async isAncestor(ancestorId: RoleId, descendantId: RoleId): Promise<boolean> {
    const ancestors = await this.getAncestors(descendantId);
    return ancestors.has(ancestorId);
  }

  /**
   * Detect circular dependencies in role hierarchy
   */
  private async detectCircular(
    role: Role,
    visited: Set<RoleId>,
    path: RoleId[]
  ): Promise<boolean> {
    if (!role.parents || role.parents.size === 0) {
      return false;
    }

    for (const parentId of role.parents) {
      // If we've seen this role in the current path, we have a cycle
      if (path.includes(parentId)) {
        return true;
      }

      // If we've visited this role in a different path, skip it
      if (visited.has(parentId)) {
        continue;
      }

      visited.add(parentId);
      const parent = await this.options.storage.getRole(parentId);

      if (!parent) {
        continue;
      }

      const hasCircular = await this.detectCircular(parent, visited, [
        ...path,
        parentId,
      ]);
      if (hasCircular) {
        return true;
      }
    }

    return false;
  }

  /**
   * Collect all ancestors recursively
   */
  private async collectAncestors(
    roleId: RoleId,
    ancestors: Set<RoleId>,
    visited: Set<RoleId>
  ): Promise<void> {
    if (visited.has(roleId)) {
      return;
    }

    visited.add(roleId);
    const role = await this.options.storage.getRole(roleId);

    if (!role || !role.parents || role.parents.size === 0) {
      return;
    }

    for (const parentId of role.parents) {
      ancestors.add(parentId);
      await this.collectAncestors(parentId, ancestors, visited);
    }
  }
}
