import { describe, it, expect, beforeEach } from 'vitest';
import { RoleHierarchy } from './role-hierarchy';
import { MemoryRBACStorage } from './storage/memory-storage';
import type { Role } from './types';

describe('RoleHierarchy', () => {
  let hierarchy: RoleHierarchy;
  let storage: MemoryRBACStorage;

  beforeEach(() => {
    storage = new MemoryRBACStorage();
    hierarchy = new RoleHierarchy({ storage, maxDepth: 10 });
  });

  describe('validateHierarchy', () => {
    it('validates simple hierarchy', async () => {
      const role: Role = {
        id: 'admin',
        name: 'Admin',
        permissions: new Set(['users:read']),
      };

      await storage.saveRole(role);
      const validation = await hierarchy.validateHierarchy('admin');

      expect(validation.valid).toBe(true);
      expect(validation.errors).toBeUndefined();
    });

    it('detects circular dependencies', async () => {
      const role1: Role = {
        id: 'role1',
        name: 'Role 1',
        permissions: new Set(),
        parents: new Set(['role2']),
      };

      const role2: Role = {
        id: 'role2',
        name: 'Role 2',
        permissions: new Set(),
        parents: new Set(['role1']),
      };

      await storage.saveRole(role1);
      await storage.saveRole(role2);

      const validation = await hierarchy.validateHierarchy('role1');
      expect(validation.valid).toBe(false);
      expect(validation.errors).toBeDefined();
      expect(validation.errors![0]).toContain('Circular dependency');
    });

    it('detects missing parent roles', async () => {
      const role: Role = {
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['nonexistent']),
      };

      await storage.saveRole(role);
      const validation = await hierarchy.validateHierarchy('admin');

      expect(validation.valid).toBe(false);
      expect(validation.errors).toBeDefined();
      expect(validation.errors![0]).toContain('does not exist');
    });

    it('warns about deep hierarchies', async () => {
      // Create a hierarchy that approaches the max depth
      for (let i = 0; i < 9; i++) {
        const role: Role = {
          id: `role${i}`,
          name: `Role ${i}`,
          permissions: new Set(),
          parents: i > 0 ? new Set([`role${i - 1}`]) : undefined,
        };
        await storage.saveRole(role);
      }

      const validation = await hierarchy.validateHierarchy('role8');
      expect(validation.valid).toBe(true);
      expect(validation.warnings).toBeDefined();
      expect(validation.warnings![0]).toContain('approaching maximum');
    });

    it('rejects too deep hierarchies', async () => {
      // Create a hierarchy that exceeds max depth
      hierarchy = new RoleHierarchy({ storage, maxDepth: 5 });

      for (let i = 0; i < 7; i++) {
        const role: Role = {
          id: `role${i}`,
          name: `Role ${i}`,
          permissions: new Set(),
          parents: i > 0 ? new Set([`role${i - 1}`]) : undefined,
        };
        await storage.saveRole(role);
      }

      const validation = await hierarchy.validateHierarchy('role6');
      expect(validation.valid).toBe(false);
      expect(validation.errors).toBeDefined();
      expect(validation.errors![0]).toContain('exceeds maximum');
    });

    it('returns error for nonexistent role', async () => {
      const validation = await hierarchy.validateHierarchy('nonexistent');
      expect(validation.valid).toBe(false);
      expect(validation.errors).toBeDefined();
      expect(validation.errors![0]).toContain('not found');
    });
  });

  describe('validateAll', () => {
    it('validates entire hierarchy system', async () => {
      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'user',
        name: 'User',
        permissions: new Set(),
      });

      const validation = await hierarchy.validateAll();
      expect(validation.valid).toBe(true);
    });

    it('reports all errors across roles', async () => {
      await storage.saveRole({
        id: 'role1',
        name: 'Role 1',
        permissions: new Set(),
        parents: new Set(['nonexistent1']),
      });

      await storage.saveRole({
        id: 'role2',
        name: 'Role 2',
        permissions: new Set(),
        parents: new Set(['nonexistent2']),
      });

      const validation = await hierarchy.validateAll();
      expect(validation.valid).toBe(false);
      expect(validation.errors).toHaveLength(2);
    });
  });

  describe('calculateDepth', () => {
    it('calculates depth of flat role', async () => {
      await storage.saveRole({
        id: 'user',
        name: 'User',
        permissions: new Set(),
      });

      const depth = await hierarchy.calculateDepth('user');
      expect(depth).toBe(1);
    });

    it('calculates depth with single parent', async () => {
      await storage.saveRole({
        id: 'user',
        name: 'User',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['user']),
      });

      const depth = await hierarchy.calculateDepth('admin');
      expect(depth).toBe(2);
    });

    it('calculates depth with multiple ancestors', async () => {
      await storage.saveRole({
        id: 'viewer',
        name: 'Viewer',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'editor',
        name: 'Editor',
        permissions: new Set(),
        parents: new Set(['viewer']),
      });

      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['editor']),
      });

      const depth = await hierarchy.calculateDepth('admin');
      expect(depth).toBe(3);
    });

    it('handles circular dependencies gracefully', async () => {
      await storage.saveRole({
        id: 'role1',
        name: 'Role 1',
        permissions: new Set(),
        parents: new Set(['role2']),
      });

      await storage.saveRole({
        id: 'role2',
        name: 'Role 2',
        permissions: new Set(),
        parents: new Set(['role1']),
      });

      const depth = await hierarchy.calculateDepth('role1');
      expect(depth).toBeGreaterThan(0);
    });
  });

  describe('getAncestors', () => {
    it('gets all ancestor roles', async () => {
      await storage.saveRole({
        id: 'viewer',
        name: 'Viewer',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'editor',
        name: 'Editor',
        permissions: new Set(),
        parents: new Set(['viewer']),
      });

      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['editor']),
      });

      const ancestors = await hierarchy.getAncestors('admin');
      expect(ancestors).toContain('editor');
      expect(ancestors).toContain('viewer');
      expect(ancestors.size).toBe(2);
    });

    it('returns empty set for role without parents', async () => {
      await storage.saveRole({
        id: 'user',
        name: 'User',
        permissions: new Set(),
      });

      const ancestors = await hierarchy.getAncestors('user');
      expect(ancestors.size).toBe(0);
    });

    it('handles multiple parent paths', async () => {
      await storage.saveRole({
        id: 'base1',
        name: 'Base 1',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'base2',
        name: 'Base 2',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['base1', 'base2']),
      });

      const ancestors = await hierarchy.getAncestors('admin');
      expect(ancestors).toContain('base1');
      expect(ancestors).toContain('base2');
    });
  });

  describe('getDescendants', () => {
    it('gets all descendant roles', async () => {
      await storage.saveRole({
        id: 'viewer',
        name: 'Viewer',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'editor',
        name: 'Editor',
        permissions: new Set(),
        parents: new Set(['viewer']),
      });

      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['editor']),
      });

      const descendants = await hierarchy.getDescendants('viewer');
      expect(descendants).toContain('editor');
      expect(descendants).toContain('admin');
      expect(descendants.size).toBe(2);
    });

    it('returns empty set for role without descendants', async () => {
      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
      });

      const descendants = await hierarchy.getDescendants('admin');
      expect(descendants.size).toBe(0);
    });
  });

  describe('isAncestor', () => {
    it('checks if role is ancestor', async () => {
      await storage.saveRole({
        id: 'viewer',
        name: 'Viewer',
        permissions: new Set(),
      });

      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
        parents: new Set(['viewer']),
      });

      const isAncestor = await hierarchy.isAncestor('viewer', 'admin');
      expect(isAncestor).toBe(true);

      const isNotAncestor = await hierarchy.isAncestor('admin', 'viewer');
      expect(isNotAncestor).toBe(false);
    });
  });
});
