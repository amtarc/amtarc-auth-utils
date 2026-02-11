import { describe, it, expect } from 'vitest';
import { createSession } from '../session/create-session';

describe('createSession', () => {
  it('should create a session with default options', () => {
    const session = createSession('user-123');

    expect(session.id).toBeDefined();
    expect(session.id).toMatch(/^session_/);
    expect(session.userId).toBe('user-123');
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.createdAt).toBeInstanceOf(Date);
    expect(session.lastActivityAt).toBeInstanceOf(Date);
  });

  it('should create a session with custom expiration', () => {
    const expiresIn = 1000 * 60 * 30; // 30 minutes
    const session = createSession('user-123', { expiresIn });

    const expectedExpiry = new Date(session.createdAt.getTime() + expiresIn);
    expect(session.expiresAt.getTime()).toBeCloseTo(
      expectedExpiry.getTime(),
      -2
    );
  });

  it('should generate unique session IDs', () => {
    const session1 = createSession('user-123');
    const session2 = createSession('user-123');

    expect(session1.id).not.toBe(session2.id);
  });

  it('should set fingerprint metadata when enabled', () => {
    const session = createSession('user-123', { fingerprint: true });

    expect(session.metadata).toBeDefined();
    expect(session.metadata?.fingerprint).toBe(true);
  });

  it('should not set metadata when fingerprint is disabled', () => {
    const session = createSession('user-123', { fingerprint: false });

    expect(session.metadata).toBeUndefined();
  });
});
