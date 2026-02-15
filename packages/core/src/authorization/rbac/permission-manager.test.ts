import { describe, it, expect, beforeEach } from 'vitest';
import { PermissionManager } from './permission-manager';
import { MemoryRBACStorage } from './storage/memory-storage';

describe('PermissionManager', () => {
  let manager: PermissionManager;
  let storage: MemoryRBACStorage;

  beforeEach(() => {
    storage = new MemoryRBACStorage();
    manager = new PermissionManager({ storage });
  });

  describe('definePermission', () => {
    it('creates new permission with auto-generated ID', async () => {
      const permission = await manager.definePermission({
        name: 'Read Users',
        description: 'View user information',
      });

      expect(permission.id).toBe('read:users');
      expect(permission.name).toBe('Read Users');
    });

    it('creates permission with custom ID', async () => {
      const permission = await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
      });

      expect(permission.id).toBe('users:read');
    });

    it('creates permission with resource type and actions', async () => {
      const permission = await manager.definePermission({
        id: 'posts:manage',
        name: 'Manage Posts',
        resourceType: 'post',
        actions: ['create', 'read', 'update', 'delete'],
      });

      expect(permission.resourceType).toBe('post');
      expect(permission.actions).toEqual([
        'create',
        'read',
        'update',
        'delete',
      ]);
    });

    it('throws if permission already exists', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
      });

      await expect(
        manager.definePermission({
          id: 'users:read',
          name: 'Another Name',
        })
      ).rejects.toThrow('already exists');
    });

    it('generates consistent IDs from names', async () => {
      const p1 = await manager.definePermission({ name: 'Read Users' });
      const p2 = await manager.definePermission({ name: 'Write Posts' });
      const p3 = await manager.definePermission({ name: 'Delete Comments' });

      expect(p1.id).toBe('read:users');
      expect(p2.id).toBe('write:posts');
      expect(p3.id).toBe('delete:comments');
    });
  });

  describe('updatePermission', () => {
    it('updates existing permission', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
      });

      const updated = await manager.updatePermission('users:read', {
        description: 'View user information',
      });

      expect(updated.id).toBe('users:read');
      expect(updated.description).toBe('View user information');
    });

    it('throws if permission not found', async () => {
      await expect(
        manager.updatePermission('nonexistent', { description: 'test' })
      ).rejects.toThrow('not found');
    });

    it('preserves ID even if included in updates', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
      });

      const updated = await manager.updatePermission('users:read', {
        name: 'Updated Name',
      });

      expect(updated.id).toBe('users:read');
      expect(updated.name).toBe('Updated Name');
    });
  });

  describe('deletePermission', () => {
    it('deletes existing permission', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
      });

      await manager.deletePermission('users:read');
      const retrieved = await manager.getPermission('users:read');

      expect(retrieved).toBeNull();
    });

    it('throws if permission not found', async () => {
      await expect(manager.deletePermission('nonexistent')).rejects.toThrow(
        'not found'
      );
    });
  });

  describe('getPermission', () => {
    it('retrieves existing permission', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
      });

      const retrieved = await manager.getPermission('users:read');
      expect(retrieved?.id).toBe('users:read');
    });

    it('returns null for nonexistent permission', async () => {
      const retrieved = await manager.getPermission('nonexistent');
      expect(retrieved).toBeNull();
    });
  });

  describe('listPermissions', () => {
    it('lists all permissions', async () => {
      await manager.definePermission({ id: 'p1', name: 'P1' });
      await manager.definePermission({ id: 'p2', name: 'P2' });
      await manager.definePermission({ id: 'p3', name: 'P3' });

      const permissions = await manager.listPermissions();
      expect(permissions).toHaveLength(3);
      expect(permissions.map((p) => p.id).sort()).toEqual(['p1', 'p2', 'p3']);
    });

    it('returns empty array when no permissions', async () => {
      const permissions = await manager.listPermissions();
      expect(permissions).toEqual([]);
    });
  });

  describe('listPermissionsByResourceType', () => {
    it('filters permissions by resource type', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
        resourceType: 'user',
      });
      await manager.definePermission({
        id: 'posts:read',
        name: 'Read Posts',
        resourceType: 'post',
      });
      await manager.definePermission({
        id: 'users:write',
        name: 'Write Users',
        resourceType: 'user',
      });

      const userPermissions =
        await manager.listPermissionsByResourceType('user');
      expect(userPermissions).toHaveLength(2);
      expect(userPermissions.map((p) => p.id).sort()).toEqual([
        'users:read',
        'users:write',
      ]);
    });

    it('returns empty array for nonexistent resource type', async () => {
      await manager.definePermission({
        id: 'users:read',
        name: 'Read Users',
        resourceType: 'user',
      });

      const permissions = await manager.listPermissionsByResourceType('post');
      expect(permissions).toEqual([]);
    });
  });

  describe('definePermissions', () => {
    it('batch creates multiple permissions', async () => {
      const permissions = await manager.definePermissions([
        { name: 'Read Users' },
        { name: 'Write Users' },
        { name: 'Delete Users' },
      ]);

      expect(permissions).toHaveLength(3);
      const list = await manager.listPermissions();
      expect(list).toHaveLength(3);
    });

    it('continues on error for duplicate permissions', async () => {
      await manager.definePermission({ id: 'p1', name: 'P1' });

      const permissions = await manager.definePermissions([
        { id: 'p1', name: 'Duplicate' }, // Will fail
        { id: 'p2', name: 'P2' }, // Should succeed
      ]);

      // Only one succeeded
      expect(permissions).toHaveLength(1);
      expect(permissions[0].id).toBe('p2');
    });

    it('handles empty array', async () => {
      const permissions = await manager.definePermissions([]);
      expect(permissions).toEqual([]);
    });
  });
});
