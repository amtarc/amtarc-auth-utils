/**
 * Double Submit CSRF Pattern Tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateDoubleSubmitToken,
  validateDoubleSubmitToken,
} from './double-submit';

describe('Double Submit Pattern', () => {
  describe('generateDoubleSubmitToken', () => {
    it('should generate double submit token', () => {
      const result = generateDoubleSubmitToken();

      expect(result.token).toBeDefined();
      expect(result.cookie).toBeDefined();
      expect(result.cookie).toContain('__Host-csrf');
      expect(result.cookie).toContain(result.token);
      expect(result.cookie).toContain('HttpOnly');
      expect(result.cookie).toContain('Secure');
      expect(result.cookie).toContain('SameSite=strict');
    });
  });

  describe('validateDoubleSubmitToken', () => {
    it('should validate matching tokens', () => {
      const token = 'test-csrf-token';

      const result = validateDoubleSubmitToken(token, token);
      expect(result.valid).toBe(true);
    });

    it('should reject non-matching tokens', () => {
      const result = validateDoubleSubmitToken('token1', 'token2');
      expect(result.valid).toBe(false);
    });

    it('should reject missing tokens', () => {
      const result = validateDoubleSubmitToken(undefined as any, 'token');
      expect(result.valid).toBe(false);
      expect(result.reason).toBe('missing');
    });
  });
});
