import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryRBACStorage } from './memory-storage';
import type { Role, Permission, UserRole } from '../types';

describe('MemoryRBACStorage', () => {
  let storage: MemoryRBACStorage;

  beforeEach(() => {
    storage = new MemoryRBACStorage();
  });

  describe('Role operations', () => {
    it('saves and retrieves role', async () => {
      const role: Role = {
        id: 'admin',
        name: 'Administrator',
        description: 'Full system access',
        permissions: new Set(['users:read', 'users:write']),
      };

      await storage.saveRole(role);
      const retrieved = await storage.getRole('admin');

      expect(retrieved).toBeTruthy();
      expect(retrieved?.id).toBe('admin');
      expect(retrieved?.name).toBe('Administrator');
      expect(retrieved?.permissions).toEqual(
        new Set(['users:read', 'users:write'])
      );
      expect(retrieved?.createdAt).toBeGreaterThan(0);
    });

    it('updates existing role', async () => {
      const role: Role = {
        id: 'admin',
        name: 'Administrator',
        permissions: new Set(['users:read']),
      };

      await storage.saveRole(role);
      const first = await storage.getRole('admin');

      // Update
      role.permissions.add('users:write');
      await storage.saveRole(role);
      const updated = await storage.getRole('admin');

      expect(updated?.permissions.size).toBe(2);
      expect(updated?.createdAt).toBe(first?.createdAt);
      expect(updated?.updatedAt).toBeGreaterThanOrEqual(first?.updatedAt || 0);
    });

    it('deletes role', async () => {
      const role: Role = {
        id: 'admin',
        name: 'Administrator',
        permissions: new Set(),
      };

      await storage.saveRole(role);
      await storage.deleteRole('admin');
      const retrieved = await storage.getRole('admin');

      expect(retrieved).toBeNull();
    });

    it('lists all roles', async () => {
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

      const roles = await storage.listRoles();
      expect(roles).toHaveLength(2);
      expect(roles.map((r) => r.id).sort()).toEqual(['admin', 'user']);
    });

    it('handles parent roles', async () => {
      const role: Role = {
        id: 'superadmin',
        name: 'Super Admin',
        permissions: new Set(['*:*']),
        parents: new Set(['admin', 'moderator']),
      };

      await storage.saveRole(role);
      const retrieved = await storage.getRole('superadmin');

      expect(retrieved?.parents).toEqual(new Set(['admin', 'moderator']));
    });
  });

  describe('Permission operations', () => {
    it('saves and retrieves permission', async () => {
      const permission: Permission = {
        id: 'users:read',
        name: 'Read Users',
        description: 'View user information',
        resourceType: 'user',
        actions: ['read', 'list'],
      };

      await storage.savePermission(permission);
      const retrieved = await storage.getPermission('users:read');

      expect(retrieved).toEqual(permission);
    });

    it('deletes permission and removes from roles', async () => {
      const permission: Permission = {
        id: 'users:read',
        name: 'Read Users',
      };

      const role: Role = {
        id: 'admin',
        name: 'Admin',
        permissions: new Set(['users:read', 'users:write']),
      };

      await storage.savePermission(permission);
      await storage.saveRole(role);
      await storage.deletePermission('users:read');

      const retrievedPermission = await storage.getPermission('users:read');
      const retrievedRole = await storage.getRole('admin');

      expect(retrievedPermission).toBeNull();
      expect(retrievedRole?.permissions).toEqual(new Set(['users:write']));
    });

    it('lists all permissions', async () => {
      await storage.savePermission({ id: 'p1', name: 'P1' });
      await storage.savePermission({ id: 'p2', name: 'P2' });

      const permissions = await storage.listPermissions();
      expect(permissions).toHaveLength(2);
    });
  });

  describe('User-role assignments', () => {
    it('assigns role to user', async () => {
      const assignment: UserRole = {
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
      };

      await storage.assignUserRole(assignment);
      const roles = await storage.getUserRoles('user1');

      expect(roles).toHaveLength(1);
      expect(roles[0].roleId).toBe('admin');
    });

    it('updates existing assignment', async () => {
      const assignment: UserRole = {
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
      };

      await storage.assignUserRole(assignment);

      // Update with expiration
      const updated: UserRole = {
        ...assignment,
        expiresAt: Date.now() + 1000,
      };
      await storage.assignUserRole(updated);

      const roles = await storage.getUserRoles('user1');
      expect(roles).toHaveLength(1);
      expect(roles[0].expiresAt).toBeDefined();
    });

    it('filters expired assignments', async () => {
      const expired: UserRole = {
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now() - 2000,
        expiresAt: Date.now() - 1000,
      };

      const valid: UserRole = {
        userId: 'user1',
        roleId: 'user',
        assignedAt: Date.now(),
      };

      await storage.assignUserRole(expired);
      await storage.assignUserRole(valid);

      const roles = await storage.getUserRoles('user1');
      expect(roles).toHaveLength(1);
      expect(roles[0].roleId).toBe('user');
    });

    it('removes user role', async () => {
      const assignment: UserRole = {
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
      };

      await storage.assignUserRole(assignment);
      await storage.removeUserRole('user1', 'admin');

      const roles = await storage.getUserRoles('user1');
      expect(roles).toHaveLength(0);
    });

    it('handles scoped assignments', async () => {
      const orgScope: UserRole = {
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
        scope: 'org:123',
      };

      const teamScope: UserRole = {
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
        scope: 'team:456',
      };

      await storage.assignUserRole(orgScope);
      await storage.assignUserRole(teamScope);

      const allRoles = await storage.getUserRoles('user1');
      expect(allRoles).toHaveLength(2);

      await storage.removeUserRole('user1', 'admin', 'org:123');
      const remaining = await storage.getUserRoles('user1');
      expect(remaining).toHaveLength(1);
      expect(remaining[0].scope).toBe('team:456');
    });

    it('lists users by role', async () => {
      await storage.assignUserRole({
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
      });
      await storage.assignUserRole({
        userId: 'user2',
        roleId: 'admin',
        assignedAt: Date.now(),
      });

      const users = await storage.listUsersByRole('admin');
      expect(users).toHaveLength(2);
      expect(users.sort()).toEqual(['user1', 'user2']);
    });

    it('cleans up on role deletion', async () => {
      const role: Role = {
        id: 'temp',
        name: 'Temp',
        permissions: new Set(),
      };

      await storage.saveRole(role);
      await storage.assignUserRole({
        userId: 'user1',
        roleId: 'temp',
        assignedAt: Date.now(),
      });

      await storage.deleteRole('temp');
      const roles = await storage.getUserRoles('user1');
      expect(roles).toHaveLength(0);
    });
  });

  describe('clear', () => {
    it('clears all data', async () => {
      await storage.saveRole({
        id: 'admin',
        name: 'Admin',
        permissions: new Set(),
      });
      await storage.savePermission({ id: 'p1', name: 'P1' });
      await storage.assignUserRole({
        userId: 'user1',
        roleId: 'admin',
        assignedAt: Date.now(),
      });

      storage.clear();

      const roles = await storage.listRoles();
      const permissions = await storage.listPermissions();
      const userRoles = await storage.getUserRoles('user1');

      expect(roles).toHaveLength(0);
      expect(permissions).toHaveLength(0);
      expect(userRoles).toHaveLength(0);
    });
  });
});
