/**
 * Encryption Tests
 */

import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptToString,
  decryptFromString,
  deriveKey,
  deriveKeyPBKDF2,
  deriveKeyScrypt,
  exportDerivedKey,
  parseDerivedKey,
  generateRandomBytes,
  generateRandomString,
  generateRandomInt,
  generateRandomAlphanumeric,
  generateUUID,
  generateSecureToken,
} from '.';

describe('Encryption', () => {
  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt text', () => {
      const key = generateRandomBytes(32);
      const plaintext = 'Hello, World!';

      const encrypted = encrypt(plaintext, { key });
      const decrypted = decrypt(encrypted, { key });

      expect(decrypted.toString('utf8')).toBe(plaintext);
    });

    it('should encrypt and decrypt buffers', () => {
      const key = generateRandomBytes(32);
      const plaintext = Buffer.from('Binary data test');

      const encrypted = encrypt(plaintext, { key });
      const decrypted = decrypt(encrypted, { key });

      expect(decrypted.toString()).toBe(plaintext.toString());
    });

    it('should include IV and auth tag', () => {
      const key = generateRandomBytes(32);
      const encrypted = encrypt('test', { key });

      expect(encrypted.iv).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.ciphertext).toBeDefined();
      expect(encrypted.algorithm).toBe('aes-256-gcm');
    });

    it('should support AAD (Additional Authenticated Data)', () => {
      const key = generateRandomBytes(32);
      const plaintext = 'Secret message';
      const aad = 'user-id-123';

      const encrypted = encrypt(plaintext, { key, aad });
      const decrypted = decrypt(encrypted, { key, aad });

      expect(decrypted.toString('utf8')).toBe(plaintext);
    });

    it('should fail decryption with wrong AAD', () => {
      const key = generateRandomBytes(32);
      const encrypted = encrypt('test', { key, aad: 'correct-aad' });

      expect(() => {
        decrypt(encrypted, { key, aad: 'wrong-aad' });
      }).toThrow('Decryption failed');
    });

    it('should fail decryption with wrong key', () => {
      const key1 = generateRandomBytes(32);
      const key2 = generateRandomBytes(32);

      const encrypted = encrypt('test', { key: key1 });

      expect(() => {
        decrypt(encrypted, { key: key2 });
      }).toThrow('Decryption failed');
    });

    it('should fail with invalid key size', () => {
      const key = generateRandomBytes(16); // Too small

      expect(() => {
        encrypt('test', { key });
      }).toThrow('Encryption key must be 32 bytes');
    });

    it('should fail decryption with tampered ciphertext', () => {
      const key = generateRandomBytes(32);
      const encrypted = encrypt('test', { key });

      // Tamper with ciphertext
      encrypted.ciphertext = encrypted.ciphertext.slice(0, -4) + 'AAAA';

      expect(() => {
        decrypt(encrypted, { key });
      }).toThrow('Decryption failed');
    });
  });

  describe('encryptToString and decryptFromString', () => {
    it('should encrypt to single string', () => {
      const key = generateRandomBytes(32);
      const plaintext = 'Hello, World!';

      const encrypted = encryptToString(plaintext, { key });

      expect(typeof encrypted).toBe('string');
      expect(encrypted.split('.').length).toBe(3);
    });

    it('should decrypt from string', () => {
      const key = generateRandomBytes(32);
      const plaintext = 'Hello, World!';

      const encrypted = encryptToString(plaintext, { key });
      const decrypted = decryptFromString(encrypted, { key });

      expect(decrypted.toString('utf8')).toBe(plaintext);
    });

    it('should fail with invalid string format', () => {
      const key = generateRandomBytes(32);

      expect(() => {
        decryptFromString('invalid-format', { key });
      }).toThrow('Invalid encrypted string format');
    });
  });

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

  describe('End-to-End Password Encryption', () => {
    it('should derive key and encrypt/decrypt data', async () => {
      const password = 'super-secret-password';
      const plaintext = 'Sensitive user data';

      // Derive key from password
      const derived = await deriveKey(password);

      // Encrypt data
      const encrypted = encrypt(plaintext, { key: derived.key });

      // Decrypt data (with same password)
      const derivedAgain = await deriveKey(password, {
        salt: derived.salt,
        algorithm: derived.algorithm as 'pbkdf2' | 'scrypt',
      });
      const decrypted = decrypt(encrypted, { key: derivedAgain.key });

      expect(decrypted.toString('utf8')).toBe(plaintext);
    });
  });
});
