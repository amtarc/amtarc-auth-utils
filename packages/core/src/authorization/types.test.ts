import { describe, it, expect } from 'vitest';
import {
  RBACAuthorizationError,
  InsufficientRoleError,
  InsufficientPermissionError,
  ResourceAccessDeniedError,
  RoleNotFoundError,
  PermissionNotFoundError,
  RoleExistsError,
  PermissionExistsError,
} from './types';

describe('Authorization Errors', () => {
  describe('RBACAuthorizationError', () => {
    it('creates error with code and context', () => {
      const error = new RBACAuthorizationError('Test error', 'TEST_CODE', {
        foo: 'bar',
      });
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.context).toEqual({ foo: 'bar' });
      expect(error.name).toBe('RBACAuthorizationError');
    });

    it('creates error without context', () => {
      const error = new RBACAuthorizationError('Test error', 'TEST_CODE');
      expect(error.message).toBe('Test error');
      expect(error.code).toBe('TEST_CODE');
      expect(error.context).toBeUndefined();
    });
  });

  describe('InsufficientRoleError', () => {
    it('creates error for single role', () => {
      const error = new InsufficientRoleError('admin');
      expect(error.message).toContain('admin');
      expect(error.code).toBe('INSUFFICIENT_ROLE');
      expect(error.name).toBe('InsufficientRoleError');
    });

    it('creates error for multiple roles', () => {
      const error = new InsufficientRoleError(['admin', 'moderator']);
      expect(error.message).toContain('admin');
      expect(error.message).toContain('moderator');
      expect(error.code).toBe('INSUFFICIENT_ROLE');
    });

    it('includes context when provided', () => {
      const context = { userId: '123', scope: 'org:456' };
      const error = new InsufficientRoleError('admin', context);
      expect(error.context).toEqual(context);
    });
  });

  describe('InsufficientPermissionError', () => {
    it('creates error for single permission', () => {
      const error = new InsufficientPermissionError('posts:delete');
      expect(error.message).toContain('posts:delete');
      expect(error.code).toBe('INSUFFICIENT_PERMISSION');
      expect(error.name).toBe('InsufficientPermissionError');
    });

    it('creates error for multiple permissions', () => {
      const error = new InsufficientPermissionError([
        'posts:read',
        'posts:write',
      ]);
      expect(error.message).toContain('posts:read');
      expect(error.message).toContain('posts:write');
    });
  });

  describe('ResourceAccessDeniedError', () => {
    it('creates error with resource and action', () => {
      const error = new ResourceAccessDeniedError('post-123', 'delete');
      expect(error.message).toContain('post-123');
      expect(error.message).toContain('delete');
      expect(error.code).toBe('RESOURCE_ACCESS_DENIED');
      expect(error.name).toBe('ResourceAccessDeniedError');
    });

    it('includes context when provided', () => {
      const context = { userId: '123' };
      const error = new ResourceAccessDeniedError(
        'post-123',
        'delete',
        context
      );
      expect(error.context).toEqual(context);
    });
  });

  describe('RoleNotFoundError', () => {
    it('creates error with role ID', () => {
      const error = new RoleNotFoundError('admin');
      expect(error.message).toContain('admin');
      expect(error.message).toContain('not found');
      expect(error.code).toBe('ROLE_NOT_FOUND');
      expect(error.name).toBe('RoleNotFoundError');
    });

    it('includes context when provided', () => {
      const context = { attemptedBy: 'user-123' };
      const error = new RoleNotFoundError('moderator', context);
      expect(error.context).toEqual(context);
    });
  });

  describe('PermissionNotFoundError', () => {
    it('creates error with permission ID', () => {
      const error = new PermissionNotFoundError('posts:delete');
      expect(error.message).toContain('posts:delete');
      expect(error.message).toContain('not found');
      expect(error.code).toBe('PERMISSION_NOT_FOUND');
      expect(error.name).toBe('PermissionNotFoundError');
    });

    it('includes context when provided', () => {
      const context = { roleId: 'admin' };
      const error = new PermissionNotFoundError('posts:publish', context);
      expect(error.context).toEqual(context);
    });
  });

  describe('RoleExistsError', () => {
    it('creates error with role ID', () => {
      const error = new RoleExistsError('admin');
      expect(error.message).toContain('admin');
      expect(error.message).toContain('already exists');
      expect(error.code).toBe('ROLE_EXISTS');
      expect(error.name).toBe('RoleExistsError');
    });

    it('includes context when provided', () => {
      const context = { existingId: 'admin-1' };
      const error = new RoleExistsError('admin', context);
      expect(error.context).toEqual(context);
    });
  });

  describe('PermissionExistsError', () => {
    it('creates error with permission ID', () => {
      const error = new PermissionExistsError('posts:delete');
      expect(error.message).toContain('posts:delete');
      expect(error.message).toContain('already exists');
      expect(error.code).toBe('PERMISSION_EXISTS');
      expect(error.name).toBe('PermissionExistsError');
    });

    it('includes context when provided', () => {
      const context = { resourceType: 'post' };
      const error = new PermissionExistsError('posts:update', context);
      expect(error.context).toEqual(context);
    });
  });
});
