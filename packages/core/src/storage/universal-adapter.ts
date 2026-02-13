/**
 * Universal Storage Adapter
 * A single storage implementation that works with all modules
 * Implements BaseStorage and CounterStorage base interfaces
 * Can be used as SessionStorageAdapter, CSRFStorageAdapter, and RateLimitStorage
 */

import type { CounterStorage } from './base-storage';
import type { StorageOptions } from '../session/storage/storage-adapter';

/**
 * In-memory universal storage adapter
 * Implements base storage interfaces and can be used for sessions, CSRF, and rate limiting
 *
 * @example
 * ```typescript
 * const storage = new UniversalMemoryStorage();
 *
 * // Use for sessions
 * await storage.set('session-123', { userId: '1' }, 3600000);
 *
 * // Use for CSRF
 * await storage.set('csrf:session-123', 'csrf-token-xyz');
 *
 * // Use for rate limiting
 * const count = await storage.increment('rate:user-123');
 * ```
 */
export class UniversalMemoryStorage implements CounterStorage {
  private store = new Map<
    string,
    { value: unknown; expiresAt?: number; metadata?: Record<string, unknown> }
  >();
  private userSessionIndex = new Map<string, Set<string>>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(options: { cleanupIntervalMs?: number } = {}) {
    const { cleanupIntervalMs = 60000 } = options;

    // Periodic cleanup of expired entries
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, cleanupIntervalMs);
    // Avoid keeping the Node.js process alive solely because of this interval
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  // ============================================================================
  // Base Storage Interface (used by all modules)
  // ============================================================================

  async get(key: string): Promise<unknown> {
    const entry = this.store.get(key);

    if (!entry) {
      return null;
    }

    // Check expiration
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    return entry.value;
  }

  async set(
    key: string,
    value: unknown,
    ttlOrOptions?: number | StorageOptions
  ): Promise<void> {
    let ttl: number | undefined;
    let metadata: Record<string, unknown> | undefined;

    // Handle both number TTL and StorageOptions object
    if (typeof ttlOrOptions === 'number') {
      ttl = ttlOrOptions;
    } else if (ttlOrOptions) {
      ttl = ttlOrOptions.ttl ? ttlOrOptions.ttl * 1000 : undefined; // Convert seconds to ms
      metadata = ttlOrOptions.metadata;
    }

    const expiresAt = ttl ? Date.now() + ttl : undefined;
    const entry: {
      value: unknown;
      expiresAt?: number;
      metadata?: Record<string, unknown>;
    } = { value };

    if (expiresAt !== undefined) {
      entry.expiresAt = expiresAt;
    }
    if (metadata !== undefined) {
      entry.metadata = metadata;
    }

    this.store.set(key, entry);

    // Track user sessions if this is session data
    if (value && typeof value === 'object' && 'userId' in value) {
      const userId = String((value as Record<string, unknown>).userId);
      if (!this.userSessionIndex.has(userId)) {
        this.userSessionIndex.set(userId, new Set());
      }
      this.userSessionIndex.get(userId)?.add(key);
    }
  }

  async delete(key: string): Promise<void> {
    // Remove from user session index if present
    const entry = this.store.get(key);
    if (
      entry?.value &&
      typeof entry.value === 'object' &&
      'userId' in entry.value
    ) {
      const userId = String((entry.value as Record<string, unknown>).userId);
      this.userSessionIndex.get(userId)?.delete(key);
      if (this.userSessionIndex.get(userId)?.size === 0) {
        this.userSessionIndex.delete(userId);
      }
    }

    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  // ============================================================================
  // Counter Storage Interface
  // ============================================================================

  async increment(key: string, amount: number = 1): Promise<number> {
    const currentValue = await this.get(key);
    const current = typeof currentValue === 'number' ? currentValue : 0;
    const newValue = current + amount;
    await this.set(key, newValue);
    return newValue;
  }

  async decrement(key: string, amount: number = 1): Promise<number> {
    return this.increment(key, -amount);
  }

  // ============================================================================
  // Session-Specific Methods
  // ============================================================================

  async touch(sessionId: string, ttl: number): Promise<void> {
    const entry = this.store.get(sessionId);
    if (entry) {
      entry.expiresAt = Date.now() + ttl * 1000;
    }
  }

  async getUserSessions(userId: string): Promise<string[]> {
    return Array.from(this.userSessionIndex.get(userId) || []);
  }

  async deleteUserSessions(userId: string): Promise<void> {
    const sessionIds = await this.getUserSessions(userId);
    for (const sessionId of sessionIds) {
      await this.delete(sessionId);
    }
    this.userSessionIndex.delete(userId);
  }

  async cleanup(): Promise<number> {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.store.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        await this.delete(key);
        cleaned++;
      }
    }

    return cleaned;
  }

  // ============================================================================
  // CSRF-Specific Methods
  // ============================================================================

  async has(key: string): Promise<boolean> {
    return this.exists(key);
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Get current number of stored entries
   */
  size(): number {
    return this.store.size;
  }

  /**
   * Clear all stored data
   */
  clear(): void {
    this.store.clear();
    this.userSessionIndex.clear();
  }

  /**
   * Stop cleanup interval and clear all data
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.clear();
  }
}
