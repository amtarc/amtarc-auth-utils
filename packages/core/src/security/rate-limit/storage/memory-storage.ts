/**
 * In-memory rate limit storage
 * For development and single-server deployments
 */

import type { RateLimitStorage } from '../types';

export class MemoryRateLimitStorage implements RateLimitStorage {
  private store = new Map<string, { value: unknown; expiresAt?: number }>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(options: { cleanupIntervalMs?: number } = {}) {
    const { cleanupIntervalMs = 60000 } = options;

    this.cleanupInterval = setInterval(() => {
      this.cleanup();
    }, cleanupIntervalMs);
    // Avoid keeping the Node.js process alive solely because of this interval
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  async get(key: string): Promise<unknown> {
    const entry = this.store.get(key);

    if (!entry) {
      return null;
    }

    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.store.delete(key);
      return null;
    }

    return entry.value;
  }

  async set(key: string, value: unknown, ttl?: number): Promise<void> {
    const expiresAt = ttl ? Date.now() + ttl : undefined;
    this.store.set(
      key,
      expiresAt !== undefined ? { value, expiresAt } : { value }
    );
  }

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

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async exists(key: string): Promise<boolean> {
    const value = await this.get(key);
    return value !== null;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (entry.expiresAt && now > entry.expiresAt) {
        this.store.delete(key);
      }
    }
  }

  destroy(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }

  size(): number {
    return this.store.size;
  }

  clear(): void {
    this.store.clear();
  }
}

/**
 * Storage adapter interface for external implementations
 */
export interface StorageAdapter extends RateLimitStorage {}
