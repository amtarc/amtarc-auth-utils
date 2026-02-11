/**
 * @amtarc/auth-utils - Cookie Creation & Parsing Tests
 */

import { describe, it, expect } from 'vitest';
import {
  createAuthCookie,
  createAuthCookies,
  isValidCookieName,
  isValidCookieValue,
  estimateCookieSize,
} from './create-cookie';
import {
  parseAuthCookies,
  getAuthCookie,
  hasAuthCookie,
  parseSetCookie,
} from './parse-cookie';

describe('createAuthCookie', () => {
  it('should create cookie with default secure settings', () => {
    const cookie = createAuthCookie('session', 'abc123');

    expect(cookie).toContain('session=abc123');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Secure');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('Max-Age=86400');
  });

  it('should create cookie with custom options', () => {
    const cookie = createAuthCookie('theme', 'dark', {
      httpOnly: false,
      secure: false,
      sameSite: 'strict',
      path: '/app',
      maxAge: 3600,
    });

    expect(cookie).toContain('theme=dark');
    expect(cookie).not.toContain('HttpOnly');
    expect(cookie).not.toContain('Secure');
    expect(cookie).toContain('SameSite=Strict');
    expect(cookie).toContain('Path=/app');
    expect(cookie).toContain('Max-Age=3600');
  });

  it('should include domain if specified', () => {
    const cookie = createAuthCookie('id', '123', {
      domain: '.example.com',
    });

    expect(cookie).toContain('Domain=.example.com');
  });

  it('should URL encode name and value', () => {
    const cookie = createAuthCookie('my cookie', 'hello world');

    expect(cookie).toContain('my%20cookie=hello%20world');
  });

  it('should support sameSite=none', () => {
    const cookie = createAuthCookie('cross', 'site', {
      sameSite: 'none',
    });

    expect(cookie).toContain('SameSite=None');
  });

  it('should handle maxAge of 0 for deletion', () => {
    const cookie = createAuthCookie('old', '', {
      maxAge: 0,
    });

    expect(cookie).toContain('Max-Age=0');
  });

  it('should use expires if provided without maxAge', () => {
    const expires = new Date('2025-12-31');
    const cookie = createAuthCookie('expire', 'test', {
      expires,
      maxAge: undefined,
    });

    expect(cookie).toContain('Expires=');
    expect(cookie).not.toContain('Max-Age');
  });
});

describe('createAuthCookies', () => {
  it('should create multiple cookies', () => {
    const cookies = createAuthCookies([
      { name: 'session', value: 'abc' },
      { name: 'theme', value: 'dark', httpOnly: false },
    ]);

    expect(cookies).toHaveLength(2);
    expect(cookies[0]).toContain('session=abc');
    expect(cookies[1]).toContain('theme=dark');
  });
});

describe('isValidCookieName', () => {
  it('should accept valid cookie names', () => {
    expect(isValidCookieName('session')).toBe(true);
    expect(isValidCookieName('My-Cookie_123')).toBe(true);
    expect(isValidCookieName('__Secure-Token')).toBe(true);
  });

  it('should reject invalid cookie names', () => {
    expect(isValidCookieName('')).toBe(false);
    expect(isValidCookieName('my cookie')).toBe(false); // space
    expect(isValidCookieName('cookie;name')).toBe(false); // semicolon
    expect(isValidCookieName('cookie=name')).toBe(false); // equals
    expect(isValidCookieName('cookie(name)')).toBe(false); // parentheses
  });
});

describe('isValidCookieValue', () => {
  it('should accept valid cookie values', () => {
    expect(isValidCookieValue('abc123')).toBe(true);
    expect(isValidCookieValue('token-value_123')).toBe(true);
  });

  it('should reject invalid cookie values', () => {
    expect(isValidCookieValue('value with space')).toBe(false);
    expect(isValidCookieValue('value;semicolon')).toBe(false);
    expect(isValidCookieValue('value,comma')).toBe(false);
  });
});

describe('estimateCookieSize', () => {
  it('should estimate cookie size in bytes', () => {
    const size = estimateCookieSize('session', 'abc123');
    expect(size).toBeGreaterThan(0);
    expect(size).toBeLessThan(4096); // Should be under 4KB limit
  });

  it('should account for options', () => {
    const simple = estimateCookieSize('s', 'v');
    const complex = estimateCookieSize('session', 'value123', {
      domain: '.example.com',
      path: '/app/dashboard',
    });

    expect(complex).toBeGreaterThan(simple);
  });
});

describe('parseAuthCookies', () => {
  it('should parse cookie header', () => {
    const cookies = parseAuthCookies('session=abc123; theme=dark; lang=en');

    expect(cookies).toEqual({
      session: 'abc123',
      theme: 'dark',
      lang: 'en',
    });
  });

  it('should handle URL-encoded values', () => {
    const cookies = parseAuthCookies('name=John%20Doe; message=Hello%20World');

    expect(cookies).toEqual({
      name: 'John Doe',
      message: 'Hello World',
    });
  });

  it('should handle empty cookie header', () => {
    expect(parseAuthCookies('')).toEqual({});
    expect(parseAuthCookies(undefined)).toEqual({});
  });

  it('should handle malformed cookies gracefully', () => {
    const cookies = parseAuthCookies('valid=123; ; invalid; another=456');

    expect(cookies).toHaveProperty('valid', '123');
    expect(cookies).toHaveProperty('another', '456');
  });

  it('should handle values with equals signs', () => {
    const cookies = parseAuthCookies('token=abc=def=ghi');

    expect(cookies).toEqual({
      token: 'abc=def=ghi',
    });
  });
});

describe('getAuthCookie', () => {
  const cookieHeader = 'session=abc123; theme=dark; lang=en';

  it('should get specific cookie value', () => {
    expect(getAuthCookie(cookieHeader, 'session')).toBe('abc123');
    expect(getAuthCookie(cookieHeader, 'theme')).toBe('dark');
  });

  it('should return null for non-existent cookie', () => {
    expect(getAuthCookie(cookieHeader, 'missing')).toBeNull();
  });

  it('should return null for empty header', () => {
    expect(getAuthCookie('', 'session')).toBeNull();
    expect(getAuthCookie(undefined, 'session')).toBeNull();
  });
});

describe('hasAuthCookie', () => {
  const cookieHeader = 'session=abc123; theme=dark';

  it('should return true if cookie exists', () => {
    expect(hasAuthCookie(cookieHeader, 'session')).toBe(true);
    expect(hasAuthCookie(cookieHeader, 'theme')).toBe(true);
  });

  it('should return false if cookie does not exist', () => {
    expect(hasAuthCookie(cookieHeader, 'missing')).toBe(false);
  });

  it('should return false for empty header', () => {
    expect(hasAuthCookie('', 'session')).toBe(false);
    expect(hasAuthCookie(undefined, 'session')).toBe(false);
  });
});

describe('parseSetCookie', () => {
  it('should parse Set-Cookie header', () => {
    const parsed = parseSetCookie(
      'session=abc123; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600'
    );

    expect(parsed).toEqual({
      name: 'session',
      value: 'abc123',
      path: '/',
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      maxAge: 3600,
    });
  });

  it('should parse cookie with domain and expires', () => {
    const expires = new Date('2025-12-31').toUTCString();
    const parsed = parseSetCookie(
      `token=xyz; Domain=.example.com; Expires=${expires}`
    );

    expect(parsed).toMatchObject({
      name: 'token',
      value: 'xyz',
      domain: '.example.com',
    });
    expect(parsed?.expires).toBeInstanceOf(Date);
  });

  it('should handle minimal cookie', () => {
    const parsed = parseSetCookie('simple=value');

    expect(parsed).toEqual({
      name: 'simple',
      value: 'value',
    });
  });

  it('should return null for invalid format', () => {
    expect(parseSetCookie('')).toBeNull();
    expect(parseSetCookie('invalid')).toBeNull();
  });

  it('should parse SameSite variations', () => {
    expect(parseSetCookie('c=v; SameSite=Strict')?.sameSite).toBe('strict');
    expect(parseSetCookie('c=v; SameSite=Lax')?.sameSite).toBe('lax');
    expect(parseSetCookie('c=v; SameSite=None')?.sameSite).toBe('none');
  });
});
