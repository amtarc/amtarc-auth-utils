import { describe, it, expect, beforeEach } from 'vitest';
import { RoleManager } from './role-manager';
import { MemoryRBACStorage } from './storage/memory-storage';

describe('RoleManager', () => {
  let manager: RoleManager;
  let storage: MemoryRBACStorage;

  beforeEach(() => {
    storage = new MemoryRBACStorage();
    manager = new RoleManager({ storage });
  });

  describe('defineRole', () => {
    it('creates new role', async () => {
      const role = await manager.defineRole({
        id: 'admin',
        name: 'Administrator',
        description: 'Full system access',
        permissions: ['users:read', 'users:write'],
      });

      expect(role.id).toBe('admin');
      expect(role.name).toBe('Administrator');
      expect(role.permissions).toEqual(new Set(['users:read', 'users:write']));
    });

    it('creates role with parent roles', async () => {
      const role = await manager.defineRole({
        id: 'superadmin',
        name: 'Super Admin',
        parents: ['admin', 'moderator'],
      });

      expect(role.parents).toEqual(new Set(['admin', 'moderator']));
    });

    it('throws if role already exists', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      await expect(
        manager.defineRole({
          id: 'admin',
          name: 'Another Admin',
        })
      ).rejects.toThrow('already exists');
    });
  });

  describe('grantPermission and revokePermission', () => {
    it('grants permission to role', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      await manager.grantPermission('admin', 'users:read');
      const role = await manager.getRole('admin');

      expect(role?.permissions).toContain('users:read');
    });

    it('grants multiple permissions', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      await manager.grantPermissions('admin', [
        'users:read',
        'users:write',
        'users:delete',
      ]);
      const role = await manager.getRole('admin');

      expect(role?.permissions.size).toBe(3);
    });

    it('revokes permission from role', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
        permissions: ['users:read', 'users:write'],
      });

      await manager.revokePermission('admin', 'users:write');
      const role = await manager.getRole('admin');

      expect(role?.permissions).toEqual(new Set(['users:read']));
    });

    it('revokes multiple permissions', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
        permissions: ['users:read', 'users:write', 'users:delete'],
      });

      await manager.revokePermissions('admin', ['users:write', 'users:delete']);
      const role = await manager.getRole('admin');

      expect(role?.permissions).toEqual(new Set(['users:read']));
    });
  });

  describe('getRolePermissions', () => {
    it('gets direct permissions', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
        permissions: ['users:read', 'users:write'],
      });

      const permissions = await manager.getRolePermissions('admin');
      expect(permissions).toEqual(new Set(['users:read', 'users:write']));
    });

    it('gets inherited permissions', async () => {
      await manager.defineRole({
        id: 'user',
        name: 'User',
        permissions: ['posts:read'],
      });

      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
        permissions: ['users:read'],
        parents: ['user'],
      });

      const permissions = await manager.getRolePermissions('admin', {
        includeInherited: true,
      });

      expect(permissions).toContain('users:read');
      expect(permissions).toContain('posts:read');
    });

    it('returns empty set for nonexistent role', async () => {
      const permissions = await manager.getRolePermissions('nonexistent');
      expect(permissions).toEqual(new Set());
    });
  });

  describe('assignRole and removeRole', () => {
    it('assigns role to user', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      await manager.assignRole('user1', 'admin');
      const roles = await manager.getUserRoles('user1');

      expect(roles).toHaveLength(1);
      expect(roles[0].roleId).toBe('admin');
    });

    it('assigns role with scope', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      await manager.assignRole('user1', 'admin', {
        scope: 'org:123',
      });

      const roles = await manager.getUserRoles('user1');
      expect(roles[0].scope).toBe('org:123');
    });

    it('assigns role with expiration', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      const expiresAt = Date.now() + 86400000;
      await manager.assignRole('user1', 'admin', {
        expiresAt,
      });

      const roles = await manager.getUserRoles('user1');
      expect(roles[0].expiresAt).toBe(expiresAt);
    });

    it('removes role from user', async () => {
      await manager.defineRole({
        id: 'admin',
        name: 'Admin',
      });

      await manager.assignRole('user1', 'admin');
      await manager.removeRole('user1', 'admin');

      const roles = await manager.getUserRoles('user1');
      expect(roles).toHaveLength(0);
    });

    it('throws if assigning nonexistent role', async () => {
      await expect(manager.assignRole('user1', 'nonexistent')).rejects.toThrow(
        'not found'
      );
    });
  });

  describe('hasRole', () => {
    it('checks if user has role', async () => {
      await manager.defineRole({ id: 'admin', name: 'Admin' });
      await manager.assignRole('user1', 'admin');

      const hasRole = await manager.hasRole('user1', 'admin');
      expect(hasRole).toBe(true);

      const hasOtherRole = await manager.hasRole('user1', 'moderator');
      expect(hasOtherRole).toBe(false);
    });

    it('respects scope', async () => {
      await manager.defineRole({ id: 'admin', name: 'Admin' });
      await manager.assignRole('user1', 'admin', { scope: 'org:123' });

      const hasRoleInScope = await manager.hasRole('user1', 'admin', 'org:123');
      expect(hasRoleInScope).toBe(true);

      const hasRoleInOtherScope = await manager.hasRole(
        'user1',
        'admin',
        'org:456'
      );
      expect(hasRoleInOtherScope).toBe(false);
    });
  });

  describe('hasAnyRole', () => {
    it('checks if user has any of specified roles', async () => {
      await manager.defineRole({ id: 'admin', name: 'Admin' });
      await manager.defineRole({ id: 'moderator', name: 'Moderator' });
      await manager.assignRole('user1', 'moderator');

      const hasAnyRole = await manager.hasAnyRole('user1', [
        'admin',
        'moderator',
      ]);
      expect(hasAnyRole).toBe(true);

      const hasNone = await manager.hasAnyRole('user1', ['admin', 'superuser']);
      expect(hasNone).toBe(false);
    });
  });

  describe('hasAllRoles', () => {
    it('checks if user has all specified roles', async () => {
      await manager.defineRole({ id: 'admin', name: 'Admin' });
      await manager.defineRole({ id: 'moderator', name: 'Moderator' });
      await manager.assignRole('user1', 'admin');
      await manager.assignRole('user1', 'moderator');

      const hasAllRoles = await manager.hasAllRoles('user1', [
        'admin',
        'moderator',
      ]);
      expect(hasAllRoles).toBe(true);

      const missingOne = await manager.hasAllRoles('user1', [
        'admin',
        'moderator',
        'superuser',
      ]);
      expect(missingOne).toBe(false);
    });
  });

  describe('getRoleUsers', () => {
    it('lists all users with specific role', async () => {
      await manager.defineRole({ id: 'admin', name: 'Admin' });
      await manager.assignRole('user1', 'admin');
      await manager.assignRole('user2', 'admin');

      const users = await manager.getRoleUsers('admin');
      expect(users).toHaveLength(2);
      expect(users.sort()).toEqual(['user1', 'user2']);
    });
  });
});
