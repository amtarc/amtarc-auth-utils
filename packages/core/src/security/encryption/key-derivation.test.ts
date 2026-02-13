/**
 * Key Derivation Tests
 */

import { describe, it, expect } from 'vitest';
import {
  deriveKey,
  deriveKeyPBKDF2,
  deriveKeyScrypt,
  exportDerivedKey,
  parseDerivedKey,
} from './key-derivation';
import { generateRandomBytes } from './random';

describe('Key Derivation', () => {
  describe('deriveKeyPBKDF2', () => {
    it('should derive key from password', async () => {
      const result = await deriveKeyPBKDF2('mypassword');

      expect(result.key).toBeInstanceOf(Buffer);
      expect(result.key.length).toBe(32);
      expect(result.salt).toBeInstanceOf(Buffer);
      expect(result.algorithm).toBe('pbkdf2');
      expect(result.params.iterations).toBe(100000);
    });

    it('should use provided salt', async () => {
      const salt = generateRandomBytes(32);
      const result = await deriveKeyPBKDF2('mypassword', { salt });

      expect(result.salt.toString('hex')).toBe(salt.toString('hex'));
    });

    it('should support custom iterations', async () => {
      const result = await deriveKeyPBKDF2('mypassword', {
        iterations: 50000,
      });

      expect(result.params.iterations).toBe(50000);
    });

    it('should derive same key with same password and salt', async () => {
      const salt = generateRandomBytes(32);

      const result1 = await deriveKeyPBKDF2('mypassword', { salt });
      const result2 = await deriveKeyPBKDF2('mypassword', { salt });

      expect(result1.key.toString('hex')).toBe(result2.key.toString('hex'));
    });
  });

  describe('deriveKeyScrypt', () => {
    it('should derive key from password', async () => {
      const result = await deriveKeyScrypt('mypassword');

      expect(result.key).toBeInstanceOf(Buffer);
      expect(result.key.length).toBe(32);
      expect(result.salt).toBeInstanceOf(Buffer);
      expect(result.algorithm).toBe('scrypt');
      expect(result.params.cost).toBe(16384);
    });

    it('should support custom parameters', async () => {
      const result = await deriveKeyScrypt('mypassword', {
        cost: 8192,
        blockSize: 4,
        parallelization: 2,
      });

      expect(result.params.cost).toBe(8192);
      expect(result.params.blockSize).toBe(4);
      expect(result.params.parallelization).toBe(2);
    });

    it('should derive same key with same password and salt', async () => {
      const salt = generateRandomBytes(32);

      const result1 = await deriveKeyScrypt('mypassword', { salt });
      const result2 = await deriveKeyScrypt('mypassword', { salt });

      expect(result1.key.toString('hex')).toBe(result2.key.toString('hex'));
    });
  });

  describe('deriveKey', () => {
    it('should use scrypt by default', async () => {
      const result = await deriveKey('mypassword');
      expect(result.algorithm).toBe('scrypt');
    });

    it('should support algorithm selection', async () => {
      const pbkdf2Result = await deriveKey('mypassword', {
        algorithm: 'pbkdf2',
      });
      expect(pbkdf2Result.algorithm).toBe('pbkdf2');

      const scryptResult = await deriveKey('mypassword', {
        algorithm: 'scrypt',
      });
      expect(scryptResult.algorithm).toBe('scrypt');
    });
  });

  describe('exportDerivedKey and parseDerivedKey', () => {
    it('should export and parse PBKDF2 key', async () => {
      const original = await deriveKeyPBKDF2('mypassword');
      const exported = exportDerivedKey(original);

      expect(typeof exported).toBe('string');
      expect(exported).toContain('pbkdf2');

      const parsed = parseDerivedKey(exported);
      expect(parsed.algorithm).toBe('pbkdf2');
      expect(parsed.salt.toString('hex')).toBe(original.salt.toString('hex'));
      expect(parsed.params.iterations).toBe(original.params.iterations);
    });

    it('should export and parse scrypt key', async () => {
      const original = await deriveKeyScrypt('mypassword');
      const exported = exportDerivedKey(original);

      expect(exported).toContain('scrypt');

      const parsed = parseDerivedKey(exported);
      expect(parsed.algorithm).toBe('scrypt');
      expect(parsed.params.cost).toBe(original.params.cost);
    });

    it('should fail parsing invalid format', () => {
      expect(() => {
        parseDerivedKey('invalid:format');
      }).toThrow('Invalid exported key format');
    });
  });
});
