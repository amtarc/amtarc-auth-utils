/**
 * @amtarc/auth-utils - Session Storage Adapter
 * Abstract interface for session storage implementations
 */

/**
 * Abstract interface for session storage implementations
 * Allows pluggable storage backends (memory, cookie, Redis, database, etc.)
 */
export interface SessionStorageAdapter<T = unknown> {
  /**
   * Store a session
   * @param sessionId - Unique session identifier
   * @param data - Session data to store
   * @param options - Storage options (TTL, metadata, etc.)
   */
  set(sessionId: string, data: T, options?: StorageOptions): Promise<void>;

  /**
   * Retrieve a session
   * @param sessionId - Unique session identifier
   * @returns Session data or null if not found/expired
   */
  get(sessionId: string): Promise<T | null>;

  /**
   * Delete a session
   * @param sessionId - Unique session identifier
   */
  delete(sessionId: string): Promise<void>;

  /**
   * Update session expiration without modifying data
   * @param sessionId - Unique session identifier
   * @param ttl - Time to live in seconds
   */
  touch(sessionId: string, ttl: number): Promise<void>;

  /**
   * Check if session exists and is valid
   * @param sessionId - Unique session identifier
   */
  exists(sessionId: string): Promise<boolean>;

  /**
   * Get all session IDs for a user (multi-device support)
   * @param userId - User identifier
   * @returns Array of session IDs
   */
  getUserSessions(userId: string): Promise<string[]>;

  /**
   * Delete all sessions for a user
   * @param userId - User identifier
   */
  deleteUserSessions(userId: string): Promise<void>;

  /**
   * Cleanup expired sessions
   * Optional - some adapters (like Redis) handle this automatically
   * @returns Number of sessions cleaned up
   */
  cleanup?(): Promise<number>;
}

/**
 * Options for storing sessions
 */
export interface StorageOptions {
  /**
   * Time to live in seconds
   * If not provided, adapter should use a sensible default
   */
  ttl?: number;

  /**
   * Additional metadata to store with the session
   * Useful for tracking devices, IP addresses, etc.
   */
  metadata?: Record<string, unknown>;
}

/**
 * Session entry structure for storage implementations
 */
export interface SessionEntry<T = unknown> {
  /**
   * The session data
   */
  data: T;

  /**
   * When the session expires (Unix timestamp in milliseconds)
   */
  expiresAt: number;

  /**
   * Optional metadata
   */
  metadata?: Record<string, unknown>;
}
