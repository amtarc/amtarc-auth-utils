/**
 * @amtarc/auth-utils - requireAuth Guard Tests
 */

import { describe, it, expect } from 'vitest';
import { requireAuth } from './require-auth';
import { UnauthenticatedError } from '../errors';
import type { GuardContext } from './require-auth';
import type { Session } from '../types';

// Helper to create mock session
function createMockSession(overrides: Partial<Session> = {}): Session {
  return {
    id: 'session-123',
    userId: 'user-123',
    user: { id: 'user-123', email: 'user@example.com' },
    expiresAt: new Date(Date.now() + 3600000),
    createdAt: new Date(),
    lastActiveAt: new Date(),
    ...overrides,
  };
}

describe('requireAuth', () => {
  describe('basic functionality', () => {
    it('should allow authenticated user', async () => {
      const session = createMockSession();
      const guard = requireAuth();

      const context: GuardContext = {
        getSession: async () => session,
      };

      const result = await guard(context);

      expect(result.authorized).toBe(true);
      expect(result.data).toEqual(session.user);
    });

    it('should throw error for unauthenticated user', async () => {
      const guard = requireAuth();

      const context: GuardContext = {
        getSession: async () => null,
      };

      await expect(guard(context)).rejects.toThrow(UnauthenticatedError);
      await expect(guard(context)).rejects.toThrow('Authentication required');
    });

    it('should use custom error message', async () => {
      const guard = requireAuth({
        message: 'Please log in to continue',
      });

      const context: GuardContext = {
        getSession: async () => null,
      };

      await expect(guard(context)).rejects.toThrow('Please log in to continue');
    });
  });

  describe('redirect mode', () => {
    it('should return redirect instead of throwing', async () => {
      const guard = requireAuth({
        redirect: '/login',
      });

      const context: GuardContext = {
        getSession: async () => null,
      };

      const result = await guard(context);

      expect(result.authorized).toBe(false);
      expect(result.redirect).toBe('/login');
      expect(result.message).toBe('Authentication required');
    });

    it('should use custom message with redirect', async () => {
      const guard = requireAuth({
        redirect: '/login',
        message: 'Login required',
      });

      const context: GuardContext = {
        getSession: async () => null,
      };

      const result = await guard(context);

      expect(result.authorized).toBe(false);
      expect(result.redirect).toBe('/login');
      expect(result.message).toBe('Login required');
    });
  });

  describe('fingerprint validation', () => {
    it('should validate fingerprint when enabled', async () => {
      const fingerprint = 'abc123def456';
      const session = createMockSession({
        fingerprint,
      });

      const guard = requireAuth({
        validateFingerprint: true,
        strictFingerprint: false, // Don't throw on mismatch
      });

      const context: GuardContext = {
        getSession: async () => session,
        metadata: {
          userAgent: 'Mozilla/5.0',
          ip: '192.168.1.1',
        },
      };

      const result = await guard(context);

      expect(result.authorized).toBe(true);
    });

    it('should work without fingerprint validation by default', async () => {
      const session = createMockSession();
      const guard = requireAuth();

      const context: GuardContext = {
        getSession: async () => session,
        metadata: {
          userAgent: 'Mozilla/5.0',
          ip: '192.168.1.1',
        },
      };

      const result = await guard(context);

      expect(result.authorized).toBe(true);
    });

    it('should redirect on fingerprint mismatch with redirect option', async () => {
      const session = createMockSession({
        fingerprint: 'wrong-fingerprint',
      });

      const guard = requireAuth({
        validateFingerprint: true,
        redirect: '/login',
      });

      const context: GuardContext = {
        getSession: async () => session,
        metadata: {
          userAgent: 'Different Browser',
          ip: '10.0.0.1',
        },
      };

      const result = await guard(context);

      expect(result.authorized).toBe(false);
      expect(result.redirect).toBe('/login');
      expect(result.message).toContain('security validation');
    });
  });

  describe('UnauthenticatedError', () => {
    it('should create error with default message', () => {
      const error = new UnauthenticatedError();
      expect(error.message).toBe('Authentication required');
      expect(error.name).toBe('UnauthenticatedError');
    });

    it('should create error with custom message', () => {
      const error = new UnauthenticatedError('Custom message');
      expect(error.message).toBe('Custom message');
      expect(error.name).toBe('UnauthenticatedError');
    });
  });
});
