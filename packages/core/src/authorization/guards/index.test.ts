import { describe, it, expect } from 'vitest';
import {
  requirePermission,
  requireRole,
  requireResourceAccess,
  requireOwnership,
  combineGuardsAnd,
  combineGuardsOr,
  createCustomGuard,
} from './index';
import type { GuardContext } from './index';
import {
  InsufficientPermissionError,
  InsufficientRoleError,
  ResourceAccessDeniedError,
} from '../types';

describe('Authorization Guards', () => {
  describe('requirePermission', () => {
    it('grants access when user has permission', async () => {
      const guard = requirePermission('posts:delete', async (userId, perms) => {
        return userId === 'user1' && perms.includes('posts:delete');
      });

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(true);
      expect(result.reason).toContain('passed');
    });

    it('throws error when user lacks permission', async () => {
      const guard = requirePermission('posts:delete', async () => false);

      await expect(guard({ userId: 'user1' })).rejects.toThrow(
        InsufficientPermissionError
      );
    });

    it('denies when no user ID provided', async () => {
      const guard = requirePermission('posts:delete', async () => true);

      const result = await guard({});

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('No user ID');
    });

    it('handles multiple permissions', async () => {
      const guard = requirePermission(
        ['posts:read', 'posts:delete'],
        async (userId, perms) => {
          return perms.includes('posts:read') && perms.includes('posts:delete');
        }
      );

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(true);
    });
  });

  describe('requireRole', () => {
    it('grants access when user has role', async () => {
      const guard = requireRole('admin', async (userId, roles) => {
        return userId === 'user1' && roles.includes('admin');
      });

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(true);
    });

    it('throws error when user lacks role', async () => {
      const guard = requireRole('admin', async () => false);

      await expect(guard({ userId: 'user1' })).rejects.toThrow(
        InsufficientRoleError
      );
    });

    it('handles multiple roles', async () => {
      const guard = requireRole(
        ['admin', 'moderator'],
        async (userId, roles) => {
          return roles.includes('admin');
        }
      );

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(true);
    });
  });

  describe('requireResourceAccess', () => {
    it('grants access when user can access resource', async () => {
      const guard = requireResourceAccess(
        'read',
        async (userId, resourceId, action) => {
          return (
            userId === 'user1' && resourceId === 'doc1' && action === 'read'
          );
        }
      );

      const result = await guard({ userId: 'user1', resourceId: 'doc1' });

      expect(result.granted).toBe(true);
    });

    it('throws error when access denied', async () => {
      const guard = requireResourceAccess('delete', async () => false);

      await expect(
        guard({ userId: 'user1', resourceId: 'doc1' })
      ).rejects.toThrow(ResourceAccessDeniedError);
    });

    it('denies when no resource ID provided', async () => {
      const guard = requireResourceAccess('read', async () => true);

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('No resource ID');
    });
  });

  describe('requireOwnership', () => {
    it('grants access to owner', async () => {
      const guard = requireOwnership(async (resourceId) => {
        return resourceId === 'doc1' ? 'user1' : null;
      });

      const result = await guard({ userId: 'user1', resourceId: 'doc1' });

      expect(result.granted).toBe(true);
      expect(result.reason).toContain('owner');
    });

    it('throws error for non-owner', async () => {
      const guard = requireOwnership(async (resourceId) => {
        return resourceId === 'doc1' ? 'user2' : null;
      });

      await expect(
        guard({ userId: 'user1', resourceId: 'doc1' })
      ).rejects.toThrow(ResourceAccessDeniedError);
    });
  });

  describe('combineGuardsAnd', () => {
    it('passes when all guards pass', async () => {
      const guard1 = createCustomGuard(async () => true);
      const guard2 = createCustomGuard(async () => true);

      const combined = combineGuardsAnd(guard1, guard2);
      const result = await combined({ userId: 'user1' });

      expect(result.granted).toBe(true);
      expect(result.reason).toContain('All guard checks passed');
    });

    it('fails when any guard fails', async () => {
      const guard1 = createCustomGuard(async () => true);
      const guard2 = createCustomGuard(async () => false);

      const combined = combineGuardsAnd(guard1, guard2);

      await expect(combined({ userId: 'user1' })).rejects.toThrow();
    });

    it('short-circuits on first failure', async () => {
      let guard2Called = false;

      const guard1 = createCustomGuard(async () => false);
      const guard2 = createCustomGuard(async () => {
        guard2Called = true;
        return true;
      });

      const combined = combineGuardsAnd(guard1, guard2);

      try {
        await combined({ userId: 'user1' });
      } catch {
        // Expected to fail
      }

      expect(guard2Called).toBe(false);
    });
  });

  describe('combineGuardsOr', () => {
    it('passes when any guard passes', async () => {
      const guard1 = createCustomGuard(async () => false, 'First guard failed');
      const guard2 = createCustomGuard(async () => true);

      const combined = combineGuardsOr(guard1, guard2);
      const result = await combined({ userId: 'user1' });

      expect(result.granted).toBe(true);
    });

    it('fails when all guards fail', async () => {
      const guard1 = createCustomGuard(async () => false, 'Guard 1 failed');
      const guard2 = createCustomGuard(async () => false, 'Guard 2 failed');

      const combined = combineGuardsOr(guard1, guard2);
      const result = await combined({ userId: 'user1' });

      expect(result.granted).toBe(false);
      expect(result.reason).toContain('All guards failed');
    });

    it('returns on first success', async () => {
      let guard2Called = false;

      const guard1 = createCustomGuard(async () => true);
      const guard2 = createCustomGuard(async () => {
        guard2Called = true;
        return true;
      });

      const combined = combineGuardsOr(guard1, guard2);
      await combined({ userId: 'user1' });

      expect(guard2Called).toBe(false);
    });
  });

  describe('createCustomGuard', () => {
    it('creates guard with custom function', async () => {
      const guard = createCustomGuard(async (context) => {
        return context.userId === 'user1';
      });

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(true);
    });

    it('throws error with custom message', async () => {
      const guard = createCustomGuard(
        async () => false,
        'Custom error message'
      );

      const context: GuardContext = { userId: 'user1' };

      await expect(guard(context)).rejects.toThrow(InsufficientPermissionError);
    });

    it('supports synchronous functions', async () => {
      const guard = createCustomGuard((context) => {
        return context.userId === 'user1';
      });

      const result = await guard({ userId: 'user1' });

      expect(result.granted).toBe(true);
    });
  });
});
