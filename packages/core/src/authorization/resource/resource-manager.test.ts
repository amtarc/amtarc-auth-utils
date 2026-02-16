import { describe, it, expect, beforeEach } from 'vitest';
import { ResourceManager } from './resource-manager';
import { MemoryResourceStorage } from './storage/memory-storage';
import { createOwnerFullAccessRule, ResourceActions } from './ownership';

describe('ResourceManager', () => {
  let manager: ResourceManager;
  let storage: MemoryResourceStorage;

  beforeEach(() => {
    storage = new MemoryResourceStorage();
    manager = new ResourceManager({
      storage,
      ownershipRules: [createOwnerFullAccessRule('document')],
    });
  });

  describe('createResource', () => {
    it('creates a new resource with timestamps', async () => {
      const resource = await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      expect(resource.id).toBe('doc1');
      expect(resource.ownerId).toBe('user1');
      expect(resource.createdAt).toBeGreaterThan(0);
      expect(resource.updatedAt).toBeGreaterThan(0);
    });
  });

  describe('grantAccess', () => {
    it('grants access to a user', async () => {
      await manager.grantAccess('user1', 'doc1', 'document', [
        'read',
        'update',
      ]);

      const permission = await storage.getResourcePermission('user1', 'doc1');
      expect(permission).toBeTruthy();
      expect(permission?.actions.has('read')).toBe(true);
      expect(permission?.actions.has('update')).toBe(true);
    });

    it('grants single action', async () => {
      await manager.grantAccess('user1', 'doc1', 'document', 'read');

      const permission = await storage.getResourcePermission('user1', 'doc1');
      expect(permission?.actions.has('read')).toBe(true);
      expect(permission?.actions.size).toBe(1);
    });

    it('grants access with scope', async () => {
      await manager.grantAccess('user1', 'doc1', 'document', 'read', {
        scope: 'team',
      });

      const permission = await storage.getResourcePermission('user1', 'doc1');
      expect(permission?.scope).toBe('team');
    });

    it('grants access with expiration', async () => {
      const expiresAt = Date.now() + 1000;
      await manager.grantAccess('user1', 'doc1', 'document', 'read', {
        expiresAt,
      });

      const permission = await storage.getResourcePermission('user1', 'doc1');
      expect(permission?.expiresAt).toBe(expiresAt);
    });
  });

  describe('revokeAccess', () => {
    it('revokes user access', async () => {
      await manager.grantAccess('user1', 'doc1', 'document', 'read');
      await manager.revokeAccess('user1', 'doc1');

      const permission = await storage.getResourcePermission('user1', 'doc1');
      expect(permission).toBeNull();
    });
  });

  describe('canAccess', () => {
    it('returns false for non-existent resource', async () => {
      const result = await manager.canAccess('user1', 'nonexistent', 'read');

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('not found');
    });

    it('grants access based on ownership', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      const result = await manager.canAccess('user1', 'doc1', 'read');

      expect(result.granted).toBe(true);
      expect(result.isOwner).toBe(true);
      expect(result.reason).toContain('Owner');
    });

    it('grants access based on explicit permission', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      await manager.grantAccess('user2', 'doc1', 'document', 'read');

      const result = await manager.canAccess('user2', 'doc1', 'read');

      expect(result.granted).toBe(true);
      expect(result.reason).toContain('Explicit permission');
    });

    it('denies access without permission', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      const result = await manager.canAccess('user2', 'doc1', 'read');

      expect(result.granted).toBe(false);
    });

    it('denies access with wrong action', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      await manager.grantAccess('user2', 'doc1', 'document', 'read');

      const result = await manager.canAccess('user2', 'doc1', 'delete');

      expect(result.granted).toBe(false);
    });

    it('grants access with admin permission', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      await manager.grantAccess('user2', 'doc1', 'document', 'admin');

      const result = await manager.canAccess('user2', 'doc1', 'delete');

      expect(result.granted).toBe(true);
      expect(result.accessLevel).toBe('admin');
    });

    it('denies access for expired permission', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      await manager.grantAccess('user2', 'doc1', 'document', 'read', {
        expiresAt: Date.now() - 1000, // Expired
      });

      const result = await manager.canAccess('user2', 'doc1', 'read');

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('expired');
    });
  });

  describe('listUserResources', () => {
    it('lists resources user can access', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });
      await manager.createResource({
        id: 'doc2',
        type: 'document',
        ownerId: 'user2',
      });
      await manager.grantAccess('user1', 'doc2', 'document', 'read');

      const resources = await manager.listUserResources('user1', 'read');

      expect(resources).toHaveLength(2);
      expect(resources.map((r) => r.id).sort()).toEqual(['doc1', 'doc2']);
    });

    it('filters by resource type', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });
      await manager.createResource({
        id: 'proj1',
        type: 'project',
        ownerId: 'user1',
      });

      const resources = await manager.listUserResources('user1', 'read', {
        resourceType: 'document',
      });

      expect(resources).toHaveLength(1);
      expect(resources[0].id).toBe('doc1');
    });
  });

  describe('listResourceUsers', () => {
    it('lists users with access to resource', async () => {
      await manager.createResource({ id: 'doc1', type: 'document' });
      await manager.grantAccess('user1', 'doc1', 'document', 'read');
      await manager.grantAccess('user2', 'doc1', 'document', 'write');

      const users = await manager.listResourceUsers('doc1');

      expect(users).toHaveLength(2);
      expect(users.sort()).toEqual(['user1', 'user2']);
    });
  });

  describe('transferOwnership', () => {
    it('transfers resource ownership', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      await manager.transferOwnership('doc1', 'user2');

      const resource = await storage.getResource('doc1');
      expect(resource?.ownerId).toBe('user2');
    });

    it('throws error for non-existent resource', async () => {
      await expect(
        manager.transferOwnership('nonexistent', 'user2')
      ).rejects.toThrow('not found');
    });
  });

  describe('deleteResource', () => {
    it('deletes resource and all permissions', async () => {
      await manager.createResource({ id: 'doc1', type: 'document' });
      await manager.grantAccess('user1', 'doc1', 'document', 'read');
      await manager.grantAccess('user2', 'doc1', 'document', 'write');

      await manager.deleteResource('doc1');

      const resource = await storage.getResource('doc1');
      const perms1 = await storage.getResourcePermission('user1', 'doc1');
      const perms2 = await storage.getResourcePermission('user2', 'doc1');

      expect(resource).toBeNull();
      expect(perms1).toBeNull();
      expect(perms2).toBeNull();
    });
  });

  describe('ownership rules', () => {
    it('uses registered ownership rules', async () => {
      await manager.createResource({
        id: 'doc1',
        type: 'document',
        ownerId: 'user1',
      });

      const result = await manager.canAccess(
        'user1',
        'doc1',
        ResourceActions.DELETE
      );

      expect(result.granted).toBe(true);
      expect(result.isOwner).toBe(true);
    });

    it('registers new ownership rule', async () => {
      manager.registerOwnershipRule({
        id: 'project-owner',
        resourceType: 'project',
        type: 'owner',
        defaultActions: ['read', 'update'],
      });

      await manager.createResource({
        id: 'proj1',
        type: 'project',
        ownerId: 'user1',
      });

      const readResult = await manager.canAccess('user1', 'proj1', 'read');
      const deleteResult = await manager.canAccess('user1', 'proj1', 'delete');

      expect(readResult.granted).toBe(true);
      expect(deleteResult.granted).toBe(false); // delete not in default actions
    });
  });
});
