/**
 * @amtarc/auth-utils - Memory Storage Adapter
 * In-memory session storage for development and testing
 * WARNING: Not suitable for production - data lost on restart
 */

import type {
  SessionStorageAdapter,
  StorageOptions,
  SessionEntry,
} from './storage-adapter';

/**
 * In-memory session storage adapter
 *
 * @example
 * ```typescript
 * const storage = new MemoryStorageAdapter({
 *   autoCleanup: true,
 *   cleanupInterval: 60000 // 1 minute
 * });
 *
 * await storage.set('session-123', { userId: '1' }, { ttl: 3600 });
 * const session = await storage.get('session-123');
 * ```
 *
 * @warning For development only. Data is lost on restart.
 */
export class MemoryStorageAdapter<
  T = unknown,
> implements SessionStorageAdapter<T> {
  private sessions: Map<string, SessionEntry<T>>;
  private userSessions: Map<string, Set<string>>;
  // eslint-disable-next-line no-undef
  private cleanupInterval?: ReturnType<typeof setInterval>;

  constructor(options?: MemoryStorageOptions) {
    this.sessions = new Map();
    this.userSessions = new Map();

    if (options?.autoCleanup) {
      this.startAutoCleanup(options.cleanupInterval || 60000);
    }
  }

  async set(
    sessionId: string,
    data: T,
    options?: StorageOptions
  ): Promise<void> {
    const ttl = options?.ttl || 86400; // 24 hours default
    const expiresAt = Date.now() + ttl * 1000;

    this.sessions.set(sessionId, {
      data,
      expiresAt,
      metadata: options?.metadata ?? {},
    });

    // Track by user for multi-device support
    if (data && typeof data === 'object' && 'userId' in data) {
      const userId = String((data as Record<string, unknown>).userId);
      if (!this.userSessions.has(userId)) {
        this.userSessions.set(userId, new Set());
      }
      const userSet = this.userSessions.get(userId);
      if (userSet) {
        userSet.add(sessionId);
      }
    }
  }

  async get(sessionId: string): Promise<T | null> {
    const entry = this.sessions.get(sessionId);

    if (!entry) {
      return null;
    }

    // Check expiration
    if (Date.now() > entry.expiresAt) {
      await this.delete(sessionId);
      return null;
    }

    return entry.data;
  }

  async delete(sessionId: string): Promise<void> {
    const entry = this.sessions.get(sessionId);
    this.sessions.delete(sessionId);

    // Remove from user sessions tracking
    if (
      entry?.data &&
      typeof entry.data === 'object' &&
      'userId' in entry.data
    ) {
      const userId = String((entry.data as Record<string, unknown>).userId);
      const userSessions = this.userSessions.get(userId);
      if (userSessions) {
        userSessions.delete(sessionId);
        if (userSessions.size === 0) {
          this.userSessions.delete(userId);
        }
      }
    }
  }

  async touch(sessionId: string, ttl: number): Promise<void> {
    const entry = this.sessions.get(sessionId);
    if (entry) {
      entry.expiresAt = Date.now() + ttl * 1000;
    }
  }

  async exists(sessionId: string): Promise<boolean> {
    const entry = this.sessions.get(sessionId);
    if (!entry) {
      return false;
    }

    // Check if expired
    if (Date.now() > entry.expiresAt) {
      await this.delete(sessionId);
      return false;
    }

    return true;
  }

  async getUserSessions(userId: string): Promise<string[]> {
    const sessions = this.userSessions.get(userId);
    if (!sessions) {
      return [];
    }

    // Filter out expired sessions
    const validSessions: string[] = [];
    for (const sessionId of sessions) {
      if (await this.exists(sessionId)) {
        validSessions.push(sessionId);
      }
    }

    return validSessions;
  }

  async deleteUserSessions(userId: string): Promise<void> {
    const sessionIds = Array.from(this.userSessions.get(userId) || []);
    await Promise.all(sessionIds.map((id) => this.delete(id)));
  }

  async cleanup(): Promise<number> {
    let cleaned = 0;
    const now = Date.now();

    for (const [sessionId, entry] of this.sessions.entries()) {
      if (now > entry.expiresAt) {
        await this.delete(sessionId);
        cleaned++;
      }
    }

    return cleaned;
  }

  /**
   * Get statistics about stored sessions
   * Useful for monitoring and debugging
   */
  getStats(): MemoryStorageStats {
    return {
      totalSessions: this.sessions.size,
      totalUsers: this.userSessions.size,
      memoryUsage: this.estimateMemoryUsage(),
    };
  }

  /**
   * Estimate memory usage in bytes (rough approximation)
   */
  private estimateMemoryUsage(): number {
    let bytes = 0;
    for (const [key, entry] of this.sessions.entries()) {
      bytes += key.length * 2; // UTF-16
      bytes += JSON.stringify(entry.data).length * 2;
      bytes += 8; // expiresAt timestamp
    }
    return bytes;
  }

  /**
   * Start automatic cleanup of expired sessions
   */
  private startAutoCleanup(interval: number): void {
    // eslint-disable-next-line no-undef
    this.cleanupInterval = setInterval(() => {
      void this.cleanup();
    }, interval);

    // Don't prevent process from exiting
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  /**
   * Stop automatic cleanup and clear all data
   */
  destroy(): void {
    if (this.cleanupInterval) {
      // eslint-disable-next-line no-undef
      clearInterval(this.cleanupInterval);
      delete this.cleanupInterval;
    }
    this.sessions.clear();
    this.userSessions.clear();
  }
}

/**
 * Options for MemoryStorageAdapter
 */
export interface MemoryStorageOptions {
  /**
   * Enable automatic cleanup of expired sessions
   * @default false
   */
  autoCleanup?: boolean;

  /**
   * Cleanup interval in milliseconds
   * @default 60000 (1 minute)
   */
  cleanupInterval?: number;
}

/**
 * Statistics about memory storage
 */
export interface MemoryStorageStats {
  /**
   * Total number of sessions stored
   */
  totalSessions: number;

  /**
   * Total number of unique users
   */
  totalUsers: number;

  /**
   * Estimated memory usage in bytes
   */
  memoryUsage: number;
}
