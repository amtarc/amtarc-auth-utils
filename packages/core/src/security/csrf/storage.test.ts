/**
 * CSRF Storage Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { MemoryCSRFStorage } from './storage';

describe('MemoryCSRFStorage', () => {
  let storage: MemoryCSRFStorage;

  beforeEach(() => {
    storage = new MemoryCSRFStorage();
  });

  it('should store and retrieve tokens', async () => {
    await storage.set('key1', 'token1');
    const token = await storage.get('key1');
    expect(token).toBe('token1');
  });

  it('should return null for non-existent keys', async () => {
    const token = await storage.get('non-existent');
    expect(token).toBeNull();
  });

  it('should delete tokens', async () => {
    await storage.set('key1', 'token1');
    await storage.delete('key1');
    const token = await storage.get('key1');
    expect(token).toBeNull();
  });

  it('should check token existence', async () => {
    await storage.set('key1', 'token1');
    expect(await storage.has('key1')).toBe(true);
    expect(await storage.has('key2')).toBe(false);
  });

  it('should expire tokens', async () => {
    await storage.set('key1', 'token1', 100); // TTL: 100ms
    expect(await storage.get('key1')).toBe('token1');

    await new Promise((resolve) => setTimeout(resolve, 150));
    expect(await storage.get('key1')).toBeNull();
  });

  it('should cleanup expired tokens', async () => {
    await storage.set('key1', 'token1', 50); // TTL: 50ms
    await storage.set('key2', 'token2'); // no expiry

    await new Promise((resolve) => setTimeout(resolve, 100));
    storage['cleanup']();

    expect(await storage.get('key1')).toBeNull();
    expect(await storage.get('key2')).toBe('token2');
  });
});
