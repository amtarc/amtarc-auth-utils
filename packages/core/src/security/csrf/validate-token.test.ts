/**
 * CSRF Token Validation Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { validateCSRFToken } from './validate-token';
import { generateCSRFToken } from './generate-token';
import { MemoryCSRFStorage } from './storage';

describe('validateCSRFToken', () => {
  let storage: MemoryCSRFStorage;

  beforeEach(() => {
    storage = new MemoryCSRFStorage();
  });

  it('should validate a stored token', async () => {
    const token = generateCSRFToken();
    await storage.set('test-key', token);

    const result = await validateCSRFToken(token, {
      storage,
      key: 'test-key',
    });

    expect(result.valid).toBe(true);
  });

  it('should reject invalid tokens', async () => {
    await storage.set('test-key', 'valid-token');

    const result = await validateCSRFToken('invalid-token', {
      storage,
      key: 'test-key',
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('mismatch');
  });

  it('should validate timestamped tokens', async () => {
    const token = generateCSRFToken({
      includeTimestamp: true,
      lifetime: 60000,
    });

    await storage.set('test-key', token);

    const result = await validateCSRFToken(token, {
      storage,
      key: 'test-key',
    });

    expect(result.valid).toBe(true);
  });

  it('should reject expired timestamped tokens', async () => {
    const pastTime = Date.now() - 120000; // 2 minutes ago
    const expiresAt = pastTime + 60000; // expired 1 minute ago
    const token = `${pastTime}.${expiresAt}.test-token`;

    await storage.set('test-key', token);

    const result = await validateCSRFToken(token, {
      storage,
      key: 'test-key',
    });

    expect(result.valid).toBe(false);
    expect(result.reason).toBe('expired');
  });

  it('should delete token after use when deleteAfterUse is true', async () => {
    const token = generateCSRFToken();
    await storage.set('test-key', token);

    await validateCSRFToken(token, {
      storage,
      key: 'test-key',
      deleteAfterUse: true,
    });

    const exists = await storage.has('test-key');
    expect(exists).toBe(false);
  });
});
