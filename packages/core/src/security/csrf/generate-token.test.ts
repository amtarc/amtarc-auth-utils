/**
 * CSRF Token Generation Tests
 */

import { describe, it, expect } from 'vitest';
import { generateCSRFToken } from './generate-token';

describe('generateCSRFToken', () => {
  it('should generate a token with default options', () => {
    const token = generateCSRFToken();
    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);
  });

  it('should generate tokens with specified length', () => {
    const token = generateCSRFToken({ length: 64 });
    // base64url encoding makes the string longer than raw bytes
    expect(token.length).toBeGreaterThan(60);
  });

  it('should support different encodings', () => {
    const hexToken = generateCSRFToken({ encoding: 'hex' });
    expect(hexToken).toMatch(/^[0-9a-f]+$/);

    const base64Token = generateCSRFToken({ encoding: 'base64' });
    expect(base64Token).toMatch(/^[A-Za-z0-9+/]+=*$/);

    const base64urlToken = generateCSRFToken({ encoding: 'base64url' });
    expect(base64urlToken).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('should generate timestamped tokens', () => {
    const token = generateCSRFToken({ includeTimestamp: true });
    const parts = token.split('.');
    expect(parts.length).toBe(3);
    expect(parseInt(parts[0]!)).toBeGreaterThan(0);
  });
});
