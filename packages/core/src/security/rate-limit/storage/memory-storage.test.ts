/**
 * Memory Rate Limit Storage Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryRateLimitStorage } from './memory-storage';

describe('MemoryRateLimitStorage', () => {
  let storage: MemoryRateLimitStorage;

  beforeEach(() => {
    storage = new MemoryRateLimitStorage();
  });

  it('should store and retrieve values', async () => {
    await storage.set('key1', 'value1');
    const value = await storage.get('key1');
    expect(value).toBe('value1');
  });

  it('should increment values', async () => {
    await storage.set('counter', 0);
    await storage.increment('counter', 1);
    await storage.increment('counter', 2);

    const value = await storage.get('counter');
    expect(value).toBe(3);
  });

  it('should decrement values', async () => {
    await storage.set('counter', 10);
    await storage.decrement('counter', 3);

    const value = await storage.get('counter');
    expect(value).toBe(7);
  });

  it('should handle TTL expiration', async () => {
    await storage.set('key1', 'value1', 100);
    expect(await storage.get('key1')).toBe('value1');

    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(await storage.get('key1')).toBeNull();
  }, 10000);

  it('should check existence', async () => {
    await storage.set('key1', 'value1');
    expect(await storage.exists('key1')).toBe(true);
    expect(await storage.exists('key2')).toBe(false);
  });

  it('should delete values', async () => {
    await storage.set('key1', 'value1');
    await storage.delete('key1');
    expect(await storage.get('key1')).toBeNull();
  });

  it('should cleanup expired entries', async () => {
    await storage.set('key1', 'value1', 50);
    await storage.set('key2', 'value2');

    await new Promise((resolve) => setTimeout(resolve, 100));
    storage['cleanup']();

    expect(await storage.get('key1')).toBeNull();
    expect(await storage.get('key2')).toBe('value2');
  }, 10000);
});
