/**
 * @amtarc/auth-utils - Cookie Deletion & Rotation Tests
 */

import { describe, it, expect } from 'vitest';
import {
  deleteAuthCookie,
  deleteAuthCookies,
  deleteAuthCookieExact,
  deleteAuthCookieAllPaths,
} from './delete-cookie';
import {
  rotateCookie,
  rotateCookies,
  shouldRotateCookie,
} from './rotate-cookie';

describe('deleteAuthCookie', () => {
  it('should create deletion cookie', () => {
    const deleteCookie = deleteAuthCookie('session');

    expect(deleteCookie).toContain('session=');
    expect(deleteCookie).toContain('Max-Age=0');
    expect(deleteCookie).toContain('Expires=Thu, 01 Jan 1970');
  });

  it('should include path and domain', () => {
    const deleteCookie = deleteAuthCookie('session', {
      path: '/api',
      domain: '.example.com',
    });

    expect(deleteCookie).toContain('Path=/api');
    expect(deleteCookie).toContain('Domain=.example.com');
  });
});

describe('deleteAuthCookies', () => {
  it('should delete multiple cookies', () => {
    const cookies = deleteAuthCookies(['session', 'csrf', 'theme']);

    expect(cookies).toHaveLength(3);
    expect(cookies[0]).toContain('session=');
    expect(cookies[1]).toContain('csrf=');
    expect(cookies[2]).toContain('theme=');
  });
});

describe('deleteAuthCookieExact', () => {
  it('should delete cookie with exact path and domain', () => {
    const deleteCookie = deleteAuthCookieExact('session', {
      path: '/app',
      domain: 'sub.example.com',
    });

    expect(deleteCookie).toContain('Path=/app');
    expect(deleteCookie).toContain('Domain=sub.example.com');
  });
});

describe('deleteAuthCookieAllPaths', () => {
  it('should create deletion cookies for all paths', () => {
    const deletions = deleteAuthCookieAllPaths('session', [
      '/',
      '/api',
      '/admin',
    ]);

    expect(deletions).toHaveLength(3);
    expect(deletions[0]).toContain('Path=/');
    expect(deletions[1]).toContain('Path=/api');
    expect(deletions[2]).toContain('Path=/admin');
  });

  it('should include domain if specified', () => {
    const deletions = deleteAuthCookieAllPaths(
      'session',
      ['/'],
      '.example.com'
    );

    expect(deletions[0]).toContain('Domain=.example.com');
  });
});

describe('rotateCookie', () => {
  it('should create new cookie', () => {
    const rotation = rotateCookie('session', 'new-value-123');

    expect(rotation.set).toContain('session=new-value-123');
    expect(rotation.delete).toBeUndefined();
  });

  it('should include deletion cookie if requested', () => {
    const rotation = rotateCookie('session', 'new-value', {
      deleteOld: true,
    });

    expect(rotation.set).toContain('session=new-value');
    expect(rotation.delete).toContain('session=');
    expect(rotation.delete).toContain('Max-Age=0');
  });

  it('should delete old cookie with different path', () => {
    const rotation = rotateCookie('session', 'new-value', {
      path: '/app',
      oldPath: '/old',
    });

    expect(rotation.set).toContain('Path=/app');
    expect(rotation.delete).toContain('Path=/old');
  });

  it('should delete old cookie with different domain', () => {
    const rotation = rotateCookie('session', 'new-value', {
      domain: 'new.example.com',
      oldDomain: 'old.example.com',
    });

    expect(rotation.set).toContain('Domain=new.example.com');
    expect(rotation.delete).toContain('Domain=old.example.com');
  });
});

describe('rotateCookies', () => {
  it('should rotate multiple cookies', () => {
    const rotations = rotateCookies([
      { name: 'session', newValue: 'new-session' },
      { name: 'csrf', newValue: 'new-csrf' },
    ]);

    expect(rotations).toHaveLength(2);
    expect(rotations[0].set).toContain('session=new-session');
    expect(rotations[1].set).toContain('csrf=new-csrf');
  });
});

describe('shouldRotateCookie', () => {
  it('should return true if rotation threshold reached', () => {
    const createdAt = new Date(Date.now() - 50000); // 50 seconds ago
    const maxAge = 100; // 100 seconds
    const threshold = 0.5; // Rotate at 50%

    expect(shouldRotateCookie(createdAt, maxAge, threshold)).toBe(true);
  });

  it('should return false if threshold not reached', () => {
    const createdAt = new Date(Date.now() - 10000); // 10 seconds ago
    const maxAge = 100; // 100 seconds
    const threshold = 0.5; // Rotate at 50%

    expect(shouldRotateCookie(createdAt, maxAge, threshold)).toBe(false);
  });

  it('should use default threshold of 0.5', () => {
    const createdAt = new Date(Date.now() - 60000); // 60 seconds ago
    const maxAge = 100; // 100 seconds

    expect(shouldRotateCookie(createdAt, maxAge)).toBe(true);
  });

  it('should handle custom threshold', () => {
    const createdAt = new Date(Date.now() - 80000); // 80 seconds ago
    const maxAge = 100; // 100 seconds
    const threshold = 0.9; // Rotate at 90%

    expect(shouldRotateCookie(createdAt, maxAge, threshold)).toBe(false);
  });
});
