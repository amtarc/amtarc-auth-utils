import type { Session, User } from '../types';

/**
 * Creates a mock session for testing
 */
export function createMockSession<TUser extends User = User>(
  overrides: Partial<Session<TUser>> = {}
): Session<TUser> {
  const now = new Date();
  return {
    id: 'test-session-id',
    userId: 'test-user-id',
    expiresAt: new Date(now.getTime() + 1000 * 60 * 60), // 1 hour
    createdAt: now,
    lastActiveAt: now,
    ...overrides,
  };
}

/**
 * Creates a mock user for testing
 */
export function createMockUser<TUser extends User = User>(
  overrides: Partial<TUser> = {}
): TUser {
  return {
    id: 'test-user-id',
    ...overrides,
  } as TUser;
}
