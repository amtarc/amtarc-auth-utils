/**
 * @amtarc/auth-utils - requireGuest Guard Tests
 */

import { describe, it, expect } from 'vitest';
import { requireGuest } from './require-guest';
import { AlreadyAuthenticatedError } from '../errors';
import type { GuardContext } from './require-auth';
import type { Session } from '../types';

// Helper to create mock session
function createMockSession(): Session {
  return {
    id: 'session-123',
    userId: 'user-123',
    user: { id: 'user-123', email: 'user@example.com' },
    expiresAt: new Date(Date.now() + 3600000),
    createdAt: new Date(),
    lastActiveAt: new Date(),
  };
}

describe('requireGuest', () => {
  describe('basic functionality', () => {
    it('should allow guest (no session)', async () => {
      const guard = requireGuest();

      const context: GuardContext = {
        getSession: async () => null,
      };

      const result = await guard(context);

      expect(result.authorized).toBe(true);
      expect(result.data).toBeNull();
    });

    it('should throw error for authenticated user', async () => {
      const session = createMockSession();
      const guard = requireGuest();

      const context: GuardContext = {
        getSession: async () => session,
      };

      await expect(guard(context)).rejects.toThrow(AlreadyAuthenticatedError);
      await expect(guard(context)).rejects.toThrow('Already authenticated');
    });

    it('should use custom error message', async () => {
      const session = createMockSession();
      const guard = requireGuest({
        message: 'Please log out first',
      });

      const context: GuardContext = {
        getSession: async () => session,
      };

      await expect(guard(context)).rejects.toThrow('Please log out first');
    });
  });

  describe('redirect mode', () => {
    it('should return redirect instead of throwing', async () => {
      const session = createMockSession();
      const guard = requireGuest({
        redirect: '/dashboard',
      });

      const context: GuardContext = {
        getSession: async () => session,
      };

      const result = await guard(context);

      expect(result.authorized).toBe(false);
      expect(result.redirect).toBe('/dashboard');
      expect(result.message).toBe('Already authenticated');
    });

    it('should use custom message with redirect', async () => {
      const session = createMockSession();
      const guard = requireGuest({
        redirect: '/dashboard',
        message: 'You are already logged in',
      });

      const context: GuardContext = {
        getSession: async () => session,
      };

      const result = await guard(context);

      expect(result.authorized).toBe(false);
      expect(result.redirect).toBe('/dashboard');
      expect(result.message).toBe('You are already logged in');
    });
  });

  describe('AlreadyAuthenticatedError', () => {
    it('should create error with default message', () => {
      const error = new AlreadyAuthenticatedError();
      expect(error.message).toBe('Already authenticated');
      expect(error.name).toBe('AlreadyAuthenticatedError');
    });

    it('should create error with custom message', () => {
      const error = new AlreadyAuthenticatedError('Custom message');
      expect(error.message).toBe('Custom message');
      expect(error.name).toBe('AlreadyAuthenticatedError');
    });
  });
});
