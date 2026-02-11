/**
 * @amtarc/auth-utils - Cookie Signing Tests
 */

import { describe, it, expect } from 'vitest';
import {
  signCookie,
  unsignCookie,
  verifyCookieSignature,
  unsignCookieStrict,
  CookieSignatureError,
} from './sign-cookie';

const TEST_SECRET = 'this-is-a-very-secure-secret-key-for-testing-purposes';
const SHORT_SECRET = 'short';

describe('signCookie', () => {
  it('should sign a cookie value', () => {
    const signed = signCookie('user-123', TEST_SECRET);

    expect(signed).toContain('.');
    expect(signed).toContain('user-123');
    expect(signed.split('.').length).toBe(2);
  });

  it('should produce consistent signatures', () => {
    const signed1 = signCookie('value', TEST_SECRET);
    const signed2 = signCookie('value', TEST_SECRET);

    expect(signed1).toBe(signed2);
  });

  it('should produce different signatures for different values', () => {
    const signed1 = signCookie('value1', TEST_SECRET);
    const signed2 = signCookie('value2', TEST_SECRET);

    expect(signed1).not.toBe(signed2);
  });

  it('should produce different signatures for different secrets', () => {
    const secret1 = 'secret1-this-is-very-long-and-secure';
    const secret2 = 'secret2-this-is-very-long-and-secure';

    const signed1 = signCookie('value', secret1);
    const signed2 = signCookie('value', secret2);

    expect(signed1).not.toBe(signed2);
  });

  it('should throw error for empty value', () => {
    expect(() => signCookie('', TEST_SECRET)).toThrow();
  });

  it('should throw error for short secret', () => {
    expect(() => signCookie('value', SHORT_SECRET)).toThrow(
      'at least 32 characters'
    );
  });
});

describe('unsignCookie', () => {
  it('should unsign valid signed cookie', () => {
    const signed = signCookie('sensitive-data', TEST_SECRET);
    const unsigned = unsignCookie(signed, TEST_SECRET);

    expect(unsigned).toBe('sensitive-data');
  });

  it('should return null for tampered signature', () => {
    const signed = signCookie('value', TEST_SECRET);
    const tampered = signed.replace(/.$/, 'X'); // Change last character

    const unsigned = unsignCookie(tampered, TEST_SECRET);

    expect(unsigned).toBeNull();
  });

  it('should return null for tampered value', () => {
    const signed = signCookie('value', TEST_SECRET);
    const [value, sig] = signed.split('.');
    const tampered = `${value}X.${sig}`; // Change value

    const unsigned = unsignCookie(tampered, TEST_SECRET);

    expect(unsigned).toBeNull();
  });

  it('should return null for wrong secret', () => {
    const signed = signCookie('value', TEST_SECRET);
    const wrongSecret = 'wrong-secret-but-also-very-long-and-secure';

    const unsigned = unsignCookie(signed, wrongSecret);

    expect(unsigned).toBeNull();
  });

  it('should return null for unsigned cookie', () => {
    const unsigned = unsignCookie('no-signature', TEST_SECRET);

    expect(unsigned).toBeNull();
  });

  it('should return null for empty value', () => {
    expect(unsignCookie('', TEST_SECRET)).toBeNull();
  });

  it('should handle values with multiple dots', () => {
    const value = 'value.with.dots';
    const signed = signCookie(value, TEST_SECRET);
    const unsigned = unsignCookie(signed, TEST_SECRET);

    expect(unsigned).toBe('value.with.dots');
  });
});

describe('verifyCookieSignature', () => {
  it('should verify valid signature', () => {
    const signed = signCookie('value', TEST_SECRET);

    expect(verifyCookieSignature(signed, TEST_SECRET)).toBe(true);
  });

  it('should reject invalid signature', () => {
    const signed = signCookie('value', TEST_SECRET);
    const tampered = signed.replace(/.$/, 'X');

    expect(verifyCookieSignature(tampered, TEST_SECRET)).toBe(false);
  });
});

describe('unsignCookieStrict', () => {
  it('should return value for valid signature', () => {
    const signed = signCookie('value', TEST_SECRET);
    const unsigned = unsignCookieStrict(signed, TEST_SECRET);

    expect(unsigned).toBe('value');
  });

  it('should throw for invalid signature', () => {
    const signed = signCookie('value', TEST_SECRET);
    const tampered = signed.replace(/.$/, 'X');

    expect(() => unsignCookieStrict(tampered, TEST_SECRET)).toThrow(
      CookieSignatureError
    );
  });
});

describe('CookieSignatureError', () => {
  it('should create error with default message', () => {
    const error = new CookieSignatureError();
    expect(error.message).toBe('Invalid cookie signature');
    expect(error.name).toBe('CookieSignatureError');
  });

  it('should create error with custom message', () => {
    const error = new CookieSignatureError('Custom message');
    expect(error.message).toBe('Custom message');
  });
});
