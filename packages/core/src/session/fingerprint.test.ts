/**
 * @amtarc/auth-utils - Session Fingerprint Tests
 */

import { describe, it, expect } from 'vitest';
import {
  generateSessionFingerprint,
  validateFingerprint,
  compareFingerprints,
  extractFingerprintMetadata,
  type FingerprintMetadata,
} from './fingerprint';
import { FingerprintMismatchError } from '../errors';
import type { Session } from '../types';

describe('generateSessionFingerprint', () => {
  it('should generate a fingerprint from metadata', () => {
    const metadata: FingerprintMetadata = {
      userAgent: 'Mozilla/5.0',
      ip: '192.168.1.1',
      acceptLanguage: 'en-US',
      platform: 'Windows',
    };

    const fingerprint = generateSessionFingerprint(metadata);

    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBe(64); // SHA-256 hex = 64 chars
  });

  it('should generate different fingerprints for different metadata', () => {
    const metadata1: FingerprintMetadata = {
      userAgent: 'Mozilla/5.0',
      ip: '192.168.1.1',
    };

    const metadata2: FingerprintMetadata = {
      userAgent: 'Chrome/100.0',
      ip: '192.168.1.1',
    };

    const fp1 = generateSessionFingerprint(metadata1);
    const fp2 = generateSessionFingerprint(metadata2);

    expect(fp1).not.toBe(fp2);
  });

  it('should generate same fingerprint for same metadata', () => {
    const metadata: FingerprintMetadata = {
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      ip: '192.168.1.1',
      acceptLanguage: 'en-US,en;q=0.9',
    };

    const fp1 = generateSessionFingerprint(metadata);
    const fp2 = generateSessionFingerprint(metadata);

    expect(fp1).toBe(fp2);
  });

  it('should handle version numbers in user agents', () => {
    const metadata: FingerprintMetadata = {
      userAgent:
        'Mozilla/5.0 (Windows; Win64; x64) AppleWebKit/537.36 Chrome/100.0.4896.127',
      ip: '192.168.1.1',
    };

    const fingerprint = generateSessionFingerprint(metadata);

    // Fingerprint should be generated successfully
    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBe(64);
  });

  it('should handle empty metadata', () => {
    const fingerprint = generateSessionFingerprint({});

    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBe(64);
  });

  it('should handle undefined values', () => {
    const metadata: FingerprintMetadata = {
      userAgent: undefined,
      ip: '192.168.1.1',
      acceptLanguage: undefined,
    };

    const fingerprint = generateSessionFingerprint(metadata);

    expect(typeof fingerprint).toBe('string');
    expect(fingerprint.length).toBe(64);
  });

  it('should be deterministic', () => {
    const metadata: FingerprintMetadata = {
      userAgent: 'Mozilla/5.0',
      ip: '192.168.1.1',
    };

    const fingerprints = Array.from({ length: 10 }, () =>
      generateSessionFingerprint(metadata)
    );

    const allSame = fingerprints.every((fp) => fp === fingerprints[0]);
    expect(allSame).toBe(true);
  });
});

describe('validateFingerprint', () => {
  const createSession = (fingerprint?: string): Session => ({
    id: 'session-1',
    userId: '123',
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 3600000),
    lastActiveAt: new Date(),
    fingerprint,
  });

  const metadata: FingerprintMetadata = {
    userAgent: 'Mozilla/5.0',
    ip: '192.168.1.1',
    acceptLanguage: 'en-US',
  };

  it('should validate matching fingerprint', () => {
    const fingerprint = generateSessionFingerprint(metadata);
    const session = createSession(fingerprint);

    const isValid = validateFingerprint(session, metadata);

    expect(isValid).toBe(true);
  });

  it('should reject mismatched fingerprint', () => {
    const fingerprint = generateSessionFingerprint(metadata);
    const session = createSession(fingerprint);

    const differentMetadata: FingerprintMetadata = {
      ...metadata,
      ip: '10.0.0.1', // Different IP
    };

    const isValid = validateFingerprint(session, differentMetadata);

    expect(isValid).toBe(false);
  });

  it('should allow missing fingerprint by default', () => {
    const session = createSession(); // No fingerprint

    const isValid = validateFingerprint(session, metadata);

    expect(isValid).toBe(true);
  });

  it('should reject missing fingerprint when not allowed', () => {
    const session = createSession();

    const isValid = validateFingerprint(session, metadata, {
      allowMissing: false,
    });

    expect(isValid).toBe(false);
  });

  it('should throw in strict mode on mismatch', () => {
    const fingerprint = generateSessionFingerprint(metadata);
    const session = createSession(fingerprint);

    const differentMetadata: FingerprintMetadata = {
      ...metadata,
      userAgent: 'Chrome/100.0',
    };

    expect(() =>
      validateFingerprint(session, differentMetadata, { strict: true })
    ).toThrow(FingerprintMismatchError);
  });

  it('should throw with custom message in strict mode', () => {
    const fingerprint = generateSessionFingerprint(metadata);
    const session = createSession(fingerprint);

    const differentMetadata: FingerprintMetadata = {
      ...metadata,
      ip: '10.0.0.1',
    };

    expect(() =>
      validateFingerprint(session, differentMetadata, {
        strict: true,
        message: 'Possible session hijacking detected',
      })
    ).toThrow('Possible session hijacking detected');
  });

  it('should throw when fingerprint missing and not allowed in strict mode', () => {
    const session = createSession();

    expect(() =>
      validateFingerprint(session, metadata, {
        strict: true,
        allowMissing: false,
      })
    ).toThrow(FingerprintMismatchError);

    expect(() =>
      validateFingerprint(session, metadata, {
        strict: true,
        allowMissing: false,
        message: 'Custom message',
      })
    ).toThrow('Custom message');
  });

  it('should handle session with undefined fingerprint property', () => {
    const session: Session = {
      id: 'session-1',
      userId: '123',
      createdAt: new Date(),
      expiresAt: new Date(),
      lastActiveAt: new Date(),
      fingerprint: undefined,
    };

    const isValid = validateFingerprint(session, metadata);
    expect(isValid).toBe(true);
  });
});

describe('compareFingerprints', () => {
  const fp1 = 'abc123';
  const fp2 = 'abc123';
  const fp3 = 'def456';

  it('should return true for matching fingerprints', () => {
    expect(compareFingerprints(fp1, fp2)).toBe(true);
  });

  it('should return false for different fingerprints', () => {
    expect(compareFingerprints(fp1, fp3)).toBe(false);
  });

  it('should return false for undefined fingerprints', () => {
    expect(compareFingerprints(undefined, fp1)).toBe(false);
    expect(compareFingerprints(fp1, undefined)).toBe(false);
    expect(compareFingerprints(undefined, undefined)).toBe(false);
  });

  it('should return false for different length fingerprints', () => {
    expect(compareFingerprints('abc', 'abcdef')).toBe(false);
  });

  it('should use constant-time comparison', () => {
    // This is hard to test directly, but we can verify behavior
    const longFp1 = 'a'.repeat(64);
    const longFp2 = 'a'.repeat(64);
    const longFp3 = 'b'.repeat(64);

    expect(compareFingerprints(longFp1, longFp2)).toBe(true);
    expect(compareFingerprints(longFp1, longFp3)).toBe(false);
  });
});

describe('extractFingerprintMetadata', () => {
  it('should extract metadata from request object', () => {
    const request = {
      headers: {
        'user-agent': 'Mozilla/5.0',
        'accept-language': 'en-US',
      },
      ip: '192.168.1.1',
    };

    const metadata = extractFingerprintMetadata(request);

    expect(metadata.userAgent).toBe('Mozilla/5.0');
    expect(metadata.acceptLanguage).toBe('en-US');
    expect(metadata.ip).toBe('192.168.1.1');
  });

  it('should handle missing headers', () => {
    const request = {
      ip: '192.168.1.1',
    };

    const metadata = extractFingerprintMetadata(request);

    expect(metadata.ip).toBe('192.168.1.1');
    expect(metadata.userAgent).toBeUndefined();
  });

  it('should handle array header values', () => {
    const request = {
      headers: {
        'user-agent': ['Mozilla/5.0', 'Other'],
      },
      ip: '192.168.1.1',
    };

    const metadata = extractFingerprintMetadata(request);

    expect(metadata.userAgent).toBe('Mozilla/5.0'); // First value
  });

  it('should handle case-insensitive headers', () => {
    const request = {
      headers: {
        'User-Agent': 'Mozilla/5.0',
        'Accept-Language': 'en-US',
      },
      ip: '192.168.1.1',
    };

    const metadata = extractFingerprintMetadata(request);

    expect(metadata.userAgent).toBe('Mozilla/5.0');
    expect(metadata.acceptLanguage).toBe('en-US');
  });

  it('should apply overrides', () => {
    const request = {
      headers: {
        'user-agent': 'Mozilla/5.0',
      },
      ip: '192.168.1.1',
    };

    const metadata = extractFingerprintMetadata(request, {
      ip: '10.0.0.1', // Override IP
      platform: 'macOS',
    });

    expect(metadata.ip).toBe('10.0.0.1');
    expect(metadata.platform).toBe('macOS');
    expect(metadata.userAgent).toBe('Mozilla/5.0'); // Not overridden
  });

  it('should handle empty request', () => {
    const metadata = extractFingerprintMetadata({});

    expect(metadata.userAgent).toBeUndefined();
    expect(metadata.ip).toBeUndefined();
  });

  it('should extract platform header', () => {
    const request = {
      headers: {
        'sec-ch-ua-platform': '"Windows"',
      },
      ip: '192.168.1.1',
    };

    const metadata = extractFingerprintMetadata(request);

    expect(metadata.platform).toBe('"Windows"');
  });
});

describe('FingerprintMismatchError', () => {
  it('should create error with default message', () => {
    const error = new FingerprintMismatchError();

    expect(error.name).toBe('FingerprintMismatchError');
    expect(error.message).toContain('fingerprint mismatch');
  });

  it('should create error with custom message', () => {
    const error = new FingerprintMismatchError('Custom error');

    expect(error.name).toBe('FingerprintMismatchError');
    expect(error.message).toBe('Custom error');
  });

  it('should be instance of Error', () => {
    const error = new FingerprintMismatchError();

    expect(error).toBeInstanceOf(Error);
  });
});
