/**
 * Base Storage Interfaces
 * Shared storage abstractions for all modules
 */

/**
 * Minimal storage interface that all storage adapters should implement
 * Provides basic key-value operations
 */
export interface BaseStorage {
  /**
   * Retrieve a value by key
   * @param key - Storage key
   * @returns Value or null if not found/expired
   */
  get(key: string): Promise<unknown>;

  /**
   * Store a value with optional TTL
   * @param key - Storage key
   * @param value - Value to store
   * @param ttl - Time to live in milliseconds (optional)
   */
  set(key: string, value: unknown, ttl?: number): Promise<void>;

  /**
   * Delete a value by key
   * @param key - Storage key
   */
  delete(key: string): Promise<void>;

  /**
   * Check if a key exists and is not expired
   * @param key - Storage key
   * @returns True if key exists
   */
  exists(key: string): Promise<boolean>;
}

/**
 * Storage interface with counter operations
 * Extends base storage with atomic increment/decrement
 */
export interface CounterStorage extends BaseStorage {
  /**
   * Atomically increment a counter
   * @param key - Storage key
   * @param amount - Amount to increment (default: 1)
   * @returns New value after increment
   */
  increment(key: string, amount?: number): Promise<number>;

  /**
   * Atomically decrement a counter
   * @param key - Storage key
   * @param amount - Amount to decrement (default: 1)
   * @returns New value after decrement
   */
  decrement(key: string, amount?: number): Promise<number>;
}
