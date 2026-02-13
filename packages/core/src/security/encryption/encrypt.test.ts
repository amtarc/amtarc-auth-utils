/**
 * Encryption and Decryption Tests
 */

import { describe, it, expect } from 'vitest';
import {
  encrypt,
  decrypt,
  encryptToString,
  decryptFromString,
} from './encrypt';
import { generateRandomBytes } from './random';
import { deriveKey } from './key-derivation';

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
