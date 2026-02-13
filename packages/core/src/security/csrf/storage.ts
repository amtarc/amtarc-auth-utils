/**
 * CSRF token storage adapters
 * Supports multiple storage strategies for tokens
 */

import type { BaseStorage } from '../../storage/base-storage';

/**
 * CSRF storage adapter interface
 * Extends BaseStorage for compatibility with other modules
 */
export interface CSRFStorageAdapter extends BaseStorage {
  /**
   * Store a CSRF token
   * Note: For CSRF, the value should be a string (token)
   * @param key - Storage key
   * @param token - CSRF token to store
   * @param ttl - Optional time-to-live in milliseconds (duration, not timestamp)
   */
  set(key: string, token: string, ttl?: number): Promise<void>;

  /**
   * Retrieve a CSRF token
   * @param key - Storage key
   * @returns Token string or null if not found/expired
   */
  get(key: string): Promise<string | null>;

  // delete, exists, and has are inherited from BaseStorage
  // Note: has() is an alias for exists() for backward compatibility
  has?(key: string): Promise<boolean>;
}

/**
 * In-memory CSRF token storage
 * For development and single-server deployments
 */
export class MemoryCSRFStorage implements CSRFStorageAdapter {
  private tokens = new Map<string, { token: string; expiresAt?: number }>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(options: { cleanupIntervalMs?: number } = {}) {
    const { cleanupIntervalMs = 60000 } = options;

    // Periodic cleanup of expired tokens
    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, cleanupIntervalMs);
    // Avoid keeping the Node.js process alive solely because of this interval
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  async set(key: string, token: string, ttl?: number): Promise<void> {
    const expiresAt = ttl ? Date.now() + ttl : undefined;
    this.tokens.set(
      key,
      expiresAt !== undefined ? { token, expiresAt } : { token }
    );
  }

  async get(key: string): Promise<string | null> {
    const entry = this.tokens.get(key);

    if (!entry) {
      return null;
    }

    // Check expiration
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.tokens.delete(key);
      return null;
    }

    return entry.token;
  }

  async delete(key: string): Promise<void> {
    this.tokens.delete(key);
  }

  async has(key: string): Promise<boolean> {
    const token = await this.get(key);
    return token !== null;
  }

  async exists(key: string): Promise<boolean> {
    return this.has(key);
  }

  /**
   * Clean up expired tokens
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.tokens.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        this.tokens.delete(key);
      }
    }
  }

  /**
   * Stop cleanup interval
   */
  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /**
   * Get current storage size
   */
  size(): number {
    return this.tokens.size;
  }

  /**
   * Clear all tokens
   */
  clear(): void {
    this.tokens.clear();
  }
}

/**
 * Session-based CSRF storage
 * Stores tokens in session data
 */
interface SessionWithCSRF {
  csrf?: Record<string, { token: string; expiresAt?: number }>;
  [key: string]: unknown;
}

export class SessionCSRFStorage implements CSRFStorageAdapter {
  constructor(private sessionGetter: () => SessionWithCSRF) {}

  async set(key: string, token: string, ttl?: number): Promise<void> {
    const session = this.sessionGetter();
    if (!session.csrf) {
      session.csrf = {};
    }
    const expiresAt = ttl ? Date.now() + ttl : undefined;
    if (expiresAt !== undefined) {
      session.csrf[key] = { token, expiresAt };
    } else {
      session.csrf[key] = { token };
    }
  }

  async get(key: string): Promise<string | null> {
    const session = this.sessionGetter();
    const entry = session.csrf?.[key];

    if (!entry) {
      return null;
    }

    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      if (session.csrf) {
        delete session.csrf[key];
      }
      return null;
    }

    return entry.token;
  }

  async delete(key: string): Promise<void> {
    const session = this.sessionGetter();
    if (session.csrf) {
      delete session.csrf[key];
    }
  }

  async has(key: string): Promise<boolean> {
    const token = await this.get(key);
    return token !== null;
  }

  async exists(key: string): Promise<boolean> {
    return this.has(key);
  }
}
