import { describe, it, expect } from 'vitest';
import { validateSession } from '../session/validate-session';
import { createMockSession } from '../__tests__/helpers';

describe('validateSession', () => {
  it('should validate a valid session', () => {
    const session = createMockSession();
    const result = validateSession(session);

    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('should reject an expired session', () => {
    const session = createMockSession({
      expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
    });
    const result = validateSession(session);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('expired');
  });

  it('should reject a session with invalid structure', () => {
    const session = createMockSession({ id: '' as any });
    const result = validateSession(session);

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('invalid');
  });

  it('should reject idle session when idle timeout is exceeded', () => {
    const idleTimeout = 1000 * 60 * 30; // 30 minutes
    const session = createMockSession({
      lastActiveAt: new Date(Date.now() - idleTimeout - 1000), // 31 minutes ago
    });
    const result = validateSession(session, { idleTimeout });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('idle-timeout');
  });

  it('should suggest refresh when >50% through lifetime', () => {
    const now = new Date();
    const createdAt = new Date(now.getTime() - 1000 * 60 * 60 * 13); // 13 hours ago
    const expiresAt = new Date(now.getTime() + 1000 * 60 * 60 * 11); // 11 hours from now

    const session = createMockSession({ createdAt, expiresAt });
    const result = validateSession(session);

    expect(result.valid).toBe(true);
    expect(result.shouldRefresh).toBe(true);
  });

  it('should not suggest refresh when <50% through lifetime', () => {
    const now = new Date();
    const createdAt = new Date(now.getTime() - 1000 * 60 * 60 * 2); // 2 hours ago
    const expiresAt = new Date(now.getTime() + 1000 * 60 * 60 * 22); // 22 hours from now

    const session = createMockSession({ createdAt, expiresAt });
    const result = validateSession(session);

    expect(result.valid).toBe(true);
    expect(result.shouldRefresh).toBe(false);
  });
});
