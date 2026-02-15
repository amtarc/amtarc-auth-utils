import { describe, it, expect, beforeEach } from 'vitest';
import type { RBACGuards } from './rbac-guards';
import { createRBACGuards } from './rbac-guards';
import { RoleManager } from './role-manager';
import { MemoryRBACStorage } from './storage/memory-storage';
import { InsufficientRoleError, InsufficientPermissionError } from '../types';

describe('RBACGuards', () => {
  let guards: RBACGuards;
  let roleManager: RoleManager;
  let storage: MemoryRBACStorage;

  beforeEach(async () => {
    storage = new MemoryRBACStorage();
    roleManager = new RoleManager({ storage });
    guards = createRBACGuards({ roleManager });

    // Setup test roles and permissions
    await roleManager.defineRole({
      id: 'admin',
      name: 'Administrator',
      permissions: ['users:read', 'users:write', 'users:delete'],
    });

    await roleManager.defineRole({
      id: 'moderator',
      name: 'Moderator',
      permissions: ['posts:read', 'posts:write'],
    });

    await roleManager.defineRole({
      id: 'user',
      name: 'User',
      permissions: ['posts:read'],
    });

    await roleManager.assignRole('user1', 'admin');
    await roleManager.assignRole('user2', 'moderator');
    await roleManager.assignRole('user3', 'user');
  });

  describe('requireRole', () => {
    it('allows access when user has required role', async () => {
      const result = await guards.requireRole({ userId: 'user1' }, 'admin');

      expect(result).toBe(true);
    });

    it('denies access when user lacks required role', async () => {
      await expect(
        guards.requireRole({ userId: 'user3' }, 'admin')
      ).rejects.toThrow(InsufficientRoleError);
    });

    it('respects scope', async () => {
      await roleManager.assignRole('user4', 'admin', { scope: 'org:123' });

      const allowed = await guards.requireRole(
        { userId: 'user4', scope: 'org:123' },
        'admin'
      );
      expect(allowed).toBe(true);

      await expect(
        guards.requireRole({ userId: 'user4', scope: 'org:456' }, 'admin')
      ).rejects.toThrow(InsufficientRoleError);
    });

    it('does not throw when throwOnFailure is false', async () => {
      const customGuards = createRBACGuards({
        roleManager,
        throwOnFailure: false,
      });

      const result = await customGuards.requireRole(
        { userId: 'user3' },
        'admin'
      );

      expect(result).toBe(false);
    });

    it('calls custom error handler', async () => {
      let errorHandled = false;
      const customGuards = createRBACGuards({
        roleManager,
        throwOnFailure: false,
        onError: async () => {
          errorHandled = true;
        },
      });

      await customGuards.requireRole({ userId: 'user3' }, 'admin');
      expect(errorHandled).toBe(true);
    });
  });

  describe('requireAnyRole', () => {
    it('allows access when user has any of the required roles', async () => {
      const result = await guards.requireAnyRole({ userId: 'user2' }, [
        'admin',
        'moderator',
      ]);

      expect(result).toBe(true);
    });

    it('denies access when user has none of the required roles', async () => {
      await expect(
        guards.requireAnyRole({ userId: 'user3' }, ['admin', 'moderator'])
      ).rejects.toThrow(InsufficientRoleError);
    });
  });

  describe('requireAllRoles', () => {
    it('allows access when user has all required roles', async () => {
      await roleManager.assignRole('user5', 'admin');
      await roleManager.assignRole('user5', 'moderator');

      const result = await guards.requireAllRoles({ userId: 'user5' }, [
        'admin',
        'moderator',
      ]);

      expect(result).toBe(true);
    });

    it('denies access when user lacks any of the required roles', async () => {
      await expect(
        guards.requireAllRoles({ userId: 'user1' }, ['admin', 'moderator'])
      ).rejects.toThrow(InsufficientRoleError);
    });
  });

  describe('requirePermission', () => {
    it('allows access when user has required permission', async () => {
      const result = await guards.requirePermission(
        { userId: 'user1' },
        'users:read'
      );

      expect(result).toBe(true);
    });

    it('denies access when user lacks required permission', async () => {
      await expect(
        guards.requirePermission({ userId: 'user3' }, 'users:write')
      ).rejects.toThrow(InsufficientPermissionError);
    });

    it('checks permissions from multiple roles', async () => {
      await roleManager.assignRole('user6', 'admin');
      await roleManager.assignRole('user6', 'moderator');

      const hasAdminPerm = await guards.requirePermission(
        { userId: 'user6' },
        'users:read'
      );
      expect(hasAdminPerm).toBe(true);

      const hasModeratorPerm = await guards.requirePermission(
        { userId: 'user6' },
        'posts:write'
      );
      expect(hasModeratorPerm).toBe(true);
    });
  });

  describe('requireAnyPermission', () => {
    it('allows access when user has any of the required permissions', async () => {
      const result = await guards.requireAnyPermission({ userId: 'user3' }, [
        'posts:read',
        'posts:write',
      ]);

      expect(result).toBe(true);
    });

    it('denies access when user has none of the required permissions', async () => {
      await expect(
        guards.requireAnyPermission({ userId: 'user3' }, [
          'users:read',
          'users:write',
        ])
      ).rejects.toThrow(InsufficientPermissionError);
    });
  });

  describe('requireAllPermissions', () => {
    it('allows access when user has all required permissions', async () => {
      const result = await guards.requireAllPermissions({ userId: 'user1' }, [
        'users:read',
        'users:write',
      ]);

      expect(result).toBe(true);
    });

    it('denies access when user lacks any of the required permissions', async () => {
      await expect(
        guards.requireAllPermissions({ userId: 'user2' }, [
          'posts:read',
          'users:read',
        ])
      ).rejects.toThrow(InsufficientPermissionError);
    });
  });

  describe('hasPermission', () => {
    it('checks if user has permission', async () => {
      const has = await guards.hasPermission('user1', 'users:read');
      expect(has).toBe(true);

      const hasNot = await guards.hasPermission('user3', 'users:write');
      expect(hasNot).toBe(false);
    });

    it('respects scope option', async () => {
      await roleManager.assignRole('user7', 'admin', { scope: 'org:123' });

      const hasInScope = await guards.hasPermission('user7', 'users:read', {
        scope: 'org:123',
      });
      expect(hasInScope).toBe(true);

      const hasInOtherScope = await guards.hasPermission(
        'user7',
        'users:read',
        {
          scope: 'org:456',
        }
      );
      expect(hasInOtherScope).toBe(false);
    });

    it('includes inherited permissions by default', async () => {
      await roleManager.defineRole({
        id: 'superadmin',
        name: 'Super Admin',
        parents: ['admin'],
      });

      await roleManager.assignRole('user8', 'superadmin');

      const has = await guards.hasPermission('user8', 'users:read');
      expect(has).toBe(true);
    });
  });

  describe('hasPermissions', () => {
    it('checks multiple permissions with AND mode', async () => {
      const hasAll = await guards.hasPermissions(
        'user1',
        ['users:read', 'users:write'],
        { mode: 'AND' }
      );
      expect(hasAll).toBe(true);

      const missingOne = await guards.hasPermissions(
        'user1',
        ['users:read', 'posts:read'],
        { mode: 'AND' }
      );
      expect(missingOne).toBe(false);
    });

    it('checks multiple permissions with OR mode', async () => {
      const hasAny = await guards.hasPermissions(
        'user1',
        ['users:read', 'posts:write'],
        { mode: 'OR' }
      );
      expect(hasAny).toBe(true);

      const hasNone = await guards.hasPermissions(
        'user3',
        ['users:read', 'users:write'],
        { mode: 'OR' }
      );
      expect(hasNone).toBe(false);
    });

    it('defaults to AND mode', async () => {
      const hasAll = await guards.hasPermissions('user1', [
        'users:read',
        'users:write',
      ]);
      expect(hasAll).toBe(true);
    });
  });
});
