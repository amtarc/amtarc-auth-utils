/**
 * @amtarc/auth-utils - Cookie Encryption Tests
 */

import { describe, it, expect } from 'vitest';
import {
  encryptCookie,
  decryptCookie,
  verifyEncryptedCookie,
  decryptCookieStrict,
  CookieDecryptionError,
} from './encrypt-cookie';

const TEST_SECRET = 'this-is-a-very-secure-secret-key-for-testing-purposes';
const SHORT_SECRET = 'short';

describe('encryptCookie', () => {
  it('should encrypt a cookie value', () => {
    const encrypted = encryptCookie('sensitive-data', TEST_SECRET);

    expect(encrypted).toBeDefined();
    expect(encrypted).not.toBe('sensitive-data');
    expect(encrypted.split('.').length).toBe(3); // iv.encrypted.authTag
  });

  it('should produce different ciphertexts for same value', () => {
    // Due to random IV
    const encrypted1 = encryptCookie('value', TEST_SECRET);
    const encrypted2 = encryptCookie('value', TEST_SECRET);

    expect(encrypted1).not.toBe(encrypted2);
  });

  it('should throw error for empty value', () => {
    expect(() => encryptCookie('', TEST_SECRET)).toThrow();
  });

  it('should throw error for short secret', () => {
    expect(() => encryptCookie('value', SHORT_SECRET)).toThrow(
      'at least 32 characters'
    );
  });
});

describe('decryptCookie', () => {
  it('should decrypt encrypted value', () => {
    const original = 'my-secret-session-id-12345';
    const encrypted = encryptCookie(original, TEST_SECRET);
    const decrypted = decryptCookie(encrypted, TEST_SECRET);

    expect(decrypted).toBe(original);
  });

  it('should decrypt with special characters', () => {
    const original = 'value with spaces and émojis 🎉';
    const encrypted = encryptCookie(original, TEST_SECRET);
    const decrypted = decryptCookie(encrypted, TEST_SECRET);

    expect(decrypted).toBe(original);
  });

  it('should return null for tampered ciphertext', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);
    const [iv, cipher, tag] = encrypted.split('.');
    const tampered = `${iv}.${cipher}X.${tag}`; // Tamper with ciphertext

    const decrypted = decryptCookie(tampered, TEST_SECRET);

    expect(decrypted).toBeNull();
  });

  it('should return null for tampered auth tag', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);
    const parts = encrypted.split('.');
    const tampered = `${parts[0]}.${parts[1]}.${parts[2]}X`; // Tamper with tag

    const decrypted = decryptCookie(tampered, TEST_SECRET);

    expect(decrypted).toBeNull();
  });

  it('should return null for wrong secret', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);
    const wrongSecret = 'wrong-secret-but-also-very-long-and-secure';

    const decrypted = decryptCookie(encrypted, wrongSecret);

    expect(decrypted).toBeNull();
  });

  it('should return null for invalid format', () => {
    expect(decryptCookie('invalid', TEST_SECRET)).toBeNull();
    expect(decryptCookie('too.few', TEST_SECRET)).toBeNull();
    expect(decryptCookie('', TEST_SECRET)).toBeNull();
  });

  it('should return null for missing parts', () => {
    expect(decryptCookie('..', TEST_SECRET)).toBeNull();
  });
});

describe('verifyEncryptedCookie', () => {
  it('should verify valid encrypted cookie', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);

    expect(verifyEncryptedCookie(encrypted, TEST_SECRET)).toBe(true);
  });

  it('should reject invalid encrypted cookie', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);
    // Tamper by modifying the auth tag more substantially
    const parts = encrypted.split('.');
    const tamperedAuthTag = parts[2].substring(0, parts[2].length - 2) + 'XX';
    const tampered = `${parts[0]}.${parts[1]}.${tamperedAuthTag}`;

    expect(verifyEncryptedCookie(tampered, TEST_SECRET)).toBe(false);
  });
});

describe('decryptCookieStrict', () => {
  it('should return value for valid encryption', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);
    const decrypted = decryptCookieStrict(encrypted, TEST_SECRET);

    expect(decrypted).toBe('value');
  });

  it('should throw for invalid encryption', () => {
    const encrypted = encryptCookie('value', TEST_SECRET);
    // Tamper by modifying the auth tag more substantially
    const parts = encrypted.split('.');
    const tamperedAuthTag = parts[2].substring(0, parts[2].length - 2) + 'XX';
    const tampered = `${parts[0]}.${parts[1]}.${tamperedAuthTag}`;

    expect(() => decryptCookieStrict(tampered, TEST_SECRET)).toThrow(
      CookieDecryptionError
    );
  });
});

describe('CookieDecryptionError', () => {
  it('should create error with default message', () => {
    const error = new CookieDecryptionError();
    expect(error.message).toBe('Cookie decryption failed');
    expect(error.name).toBe('CookieDecryptionError');
  });

  it('should create error with custom message', () => {
    const error = new CookieDecryptionError('Custom message');
    expect(error.message).toBe('Custom message');
  });
});
