/**
 * Random Generation Tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateRandomBytes,
  generateRandomString,
  generateRandomInt,
  generateRandomAlphanumeric,
  generateUUID,
  generateSecureToken,
} from './random';

describe('Random Generation', () => {
  describe('generateRandomBytes', () => {
    it('should generate random bytes', () => {
      const bytes = generateRandomBytes(32);
      expect(bytes).toBeInstanceOf(Buffer);
      expect(bytes.length).toBe(32);
    });

    it('should generate different values', () => {
      const bytes1 = generateRandomBytes(16);
      const bytes2 = generateRandomBytes(16);
      expect(bytes1.toString('hex')).not.toBe(bytes2.toString('hex'));
    });
  });

  describe('generateRandomString', () => {
    it('should generate hex string', () => {
      const str = generateRandomString(16, 'hex');
      expect(str).toMatch(/^[0-9a-f]{32}$/);
    });

    it('should generate base64 string', () => {
      const str = generateRandomString(16, 'base64');
      expect(str).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it('should generate base64url string', () => {
      const str = generateRandomString(16, 'base64url');
      expect(str).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  describe('generateRandomInt', () => {
    it('should generate int in range', () => {
      for (let i = 0; i < 100; i++) {
        const num = generateRandomInt(0, 10);
        expect(num).toBeGreaterThanOrEqual(0);
        expect(num).toBeLessThan(10);
      }
    });

    it('should generate different values', () => {
      const values = new Set();
      for (let i = 0; i < 100; i++) {
        values.add(generateRandomInt(0, 1000));
      }
      expect(values.size).toBeGreaterThan(50);
    });
  });

  describe('generateRandomAlphanumeric', () => {
    it('should generate alphanumeric string', () => {
      const str = generateRandomAlphanumeric(32);
      expect(str).toMatch(/^[A-Za-z0-9]{32}$/);
    });

    it('should generate strings of specified length', () => {
      expect(generateRandomAlphanumeric(10).length).toBe(10);
      expect(generateRandomAlphanumeric(50).length).toBe(50);
    });
  });

  describe('generateUUID', () => {
    it('should generate valid UUID v4', () => {
      const uuid = generateUUID();
      expect(uuid).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
      );
    });

    it('should generate unique UUIDs', () => {
      const uuids = new Set();
      for (let i = 0; i < 100; i++) {
        uuids.add(generateUUID());
      }
      expect(uuids.size).toBe(100);
    });
  });

  describe('generateSecureToken', () => {
    it('should generate token with default options', () => {
      const token = generateSecureToken();
      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(0);
    });

    it('should support different encodings', () => {
      const hex = generateSecureToken({ encoding: 'hex' });
      expect(hex).toMatch(/^[0-9a-f]+$/);

      const alphanumeric = generateSecureToken({ encoding: 'alphanumeric' });
      expect(alphanumeric).toMatch(/^[A-Za-z0-9]+$/);
    });

    it('should generate tokens of specified length', () => {
      const token = generateSecureToken({
        length: 64,
        encoding: 'alphanumeric',
      });
      expect(token.length).toBe(64);
    });
  });
});
