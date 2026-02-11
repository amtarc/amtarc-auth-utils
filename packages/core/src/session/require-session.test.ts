import { describe, it, expect } from 'vitest';
import { requireSession } from '../session/require-session';
import { createMockSession } from '../__tests__/helpers';
import { SessionExpiredError } from '../errors';

describe('requireSession', () => {
  it('should execute handler with valid session', async () => {
    const session = createMockSession();
    const getSession = () => session;

    const guard = requireSession(getSession);
    const handler = guard(async (s) => ({ userId: s.userId }));

    const result = await handler();
    expect(result.userId).toBe('test-user-id');
  });

  it('should throw error when session is null', async () => {
    const getSession = () => null;

    const guard = requireSession(getSession);
    const handler = guard(async (s) => ({ userId: s.userId }));

    await expect(handler()).rejects.toThrow(SessionExpiredError);
    await expect(handler()).rejects.toThrow('No active session found');
  });

  it('should throw error when session is expired', async () => {
    const session = createMockSession({
      expiresAt: new Date(Date.now() - 1000),
    });
    const getSession = () => session;

    const guard = requireSession(getSession);
    const handler = guard(async (s) => ({ userId: s.userId }));

    await expect(handler()).rejects.toThrow(SessionExpiredError);
  });

  it('should work with async getSession', async () => {
    const session = createMockSession();
    const getSession = async () => session;

    const guard = requireSession(getSession);
    const handler = guard(async (s) => ({ userId: s.userId }));

    const result = await handler();
    expect(result.userId).toBe('test-user-id');
  });
});
