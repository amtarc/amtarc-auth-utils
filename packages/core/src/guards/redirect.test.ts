/**
 * @amtarc/auth-utils - Redirect Management Tests
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  isValidRedirect,
  saveAuthRedirect,
  restoreAuthRedirect,
  peekAuthRedirect,
  clearAuthRedirect,
  type RedirectStorage,
} from './redirect';
import { InvalidRedirectError } from '../errors';

// Simple in-memory storage for testing
class MemoryRedirectStorage implements RedirectStorage {
  private data = new Map<string, string>();

  set(key: string, value: string): void {
    this.data.set(key, value);
  }

  get(key: string): string | null {
    return this.data.get(key) || null;
  }

  delete(key: string): void {
    this.data.delete(key);
  }

  clear(): void {
    this.data.clear();
  }
}

describe('isValidRedirect', () => {
  describe('relative URLs', () => {
    it('should allow relative URLs', () => {
      expect(isValidRedirect('/dashboard')).toBe(true);
      expect(isValidRedirect('/user/profile')).toBe(true);
      expect(isValidRedirect('/some/deep/path')).toBe(true);
    });

    it('should reject protocol-relative URLs', () => {
      expect(isValidRedirect('//evil.com')).toBe(false);
      expect(isValidRedirect('//example.com/path')).toBe(false);
    });

    it('should reject empty or whitespace URLs', () => {
      expect(isValidRedirect('')).toBe(false);
      expect(isValidRedirect('  ')).toBe(false);
      expect(isValidRedirect('\n')).toBe(false);
    });
  });

  describe('dangerous protocols', () => {
    it('should reject javascript: protocol', () => {
      expect(isValidRedirect('javascript:alert(1)')).toBe(false);
      expect(isValidRedirect('JavaScript:alert(1)')).toBe(false);
    });

    it('should reject data: protocol', () => {
      expect(isValidRedirect('data:text/html,<script>alert(1)</script>')).toBe(
        false
      );
    });

    it('should reject file: protocol', () => {
      expect(isValidRedirect('file:///etc/passwd')).toBe(false);
    });

    it('should reject vbscript: protocol', () => {
      expect(isValidRedirect('vbscript:msgbox(1)')).toBe(false);
    });
  });

  describe('absolute URLs', () => {
    it('should reject absolute URLs by default', () => {
      expect(isValidRedirect('https://example.com')).toBe(false);
      expect(isValidRedirect('http://localhost:3000')).toBe(false);
    });

    it('should allow absolute URLs with allowedHosts', () => {
      expect(
        isValidRedirect('https://app.example.com/dashboard', {
          allowedHosts: ['app.example.com'],
        })
      ).toBe(true);
    });

    it('should reject URLs not in allowedHosts', () => {
      expect(
        isValidRedirect('https://evil.com', {
          allowedHosts: ['app.example.com'],
        })
      ).toBe(false);
    });

    it('should support wildcard subdomains', () => {
      expect(
        isValidRedirect('https://api.example.com/data', {
          allowedHosts: ['*.example.com'],
        })
      ).toBe(true);

      expect(
        isValidRedirect('https://app.example.com/data', {
          allowedHosts: ['*.example.com'],
        })
      ).toBe(true);

      expect(
        isValidRedirect('https://example.com/data', {
          allowedHosts: ['*.example.com'],
        })
      ).toBe(true);
    });

    it('should allow external URLs with allowExternal', () => {
      expect(
        isValidRedirect('https://example.com', {
          allowExternal: true,
        })
      ).toBe(true);
    });
  });

  describe('path validation', () => {
    it('should validate against allowed paths (string)', () => {
      expect(
        isValidRedirect('/dashboard/profile', {
          allowedPaths: ['/dashboard'],
        })
      ).toBe(true);

      expect(
        isValidRedirect('/admin/settings', {
          allowedPaths: ['/dashboard'],
        })
      ).toBe(false);
    });

    it('should validate against allowed paths (regex)', () => {
      expect(
        isValidRedirect('/user/123/profile', {
          allowedPaths: [/^\/user\/\d+/],
        })
      ).toBe(true);

      expect(
        isValidRedirect('/user/abc/profile', {
          allowedPaths: [/^\/user\/\d+/],
        })
      ).toBe(false);
    });

    it('should support multiple allowed paths', () => {
      expect(
        isValidRedirect('/dashboard', {
          allowedPaths: ['/dashboard', '/profile', '/settings'],
        })
      ).toBe(true);

      expect(
        isValidRedirect('/admin', {
          allowedPaths: ['/dashboard', '/profile'],
        })
      ).toBe(false);
    });

    it('should work with absolute URLs and path validation', () => {
      expect(
        isValidRedirect('https://app.example.com/dashboard', {
          allowedHosts: ['app.example.com'],
          allowedPaths: ['/dashboard'],
        })
      ).toBe(true);

      expect(
        isValidRedirect('https://app.example.com/admin', {
          allowedHosts: ['app.example.com'],
          allowedPaths: ['/dashboard'],
        })
      ).toBe(false);
    });
  });
});

describe('saveAuthRedirect', () => {
  let storage: MemoryRedirectStorage;

  beforeEach(() => {
    storage = new MemoryRedirectStorage();
  });

  it('should save valid redirect URL', () => {
    saveAuthRedirect('/dashboard', storage);

    expect(storage.get('auth_redirect')).toBe('/dashboard');
  });

  it('should use custom storage key', () => {
    saveAuthRedirect('/profile', storage, { key: 'my_redirect' });

    expect(storage.get('my_redirect')).toBe('/profile');
    expect(storage.get('auth_redirect')).toBeNull();
  });

  it('should throw on invalid URL by default', () => {
    expect(() => {
      saveAuthRedirect('javascript:alert(1)', storage);
    }).toThrow(InvalidRedirectError);
  });

  it('should skip validation if disabled', () => {
    saveAuthRedirect('javascript:alert(1)', storage, { validate: false });

    expect(storage.get('auth_redirect')).toBe('javascript:alert(1)');
  });

  it('should validate with allowed paths', () => {
    expect(() => {
      saveAuthRedirect('/admin', storage, {
        allowedPaths: ['/dashboard'],
      });
    }).toThrow(InvalidRedirectError);

    saveAuthRedirect('/dashboard/settings', storage, {
      allowedPaths: ['/dashboard'],
    });

    expect(storage.get('auth_redirect')).toBe('/dashboard/settings');
  });
});

describe('restoreAuthRedirect', () => {
  let storage: MemoryRedirectStorage;

  beforeEach(() => {
    storage = new MemoryRedirectStorage();
  });

  it('should restore and clear saved redirect', () => {
    saveAuthRedirect('/profile', storage);

    const url = restoreAuthRedirect(storage);

    expect(url).toBe('/profile');
    expect(storage.get('auth_redirect')).toBeNull();
  });

  it('should return fallback if no redirect saved', () => {
    const url = restoreAuthRedirect(storage, { fallback: '/dashboard' });

    expect(url).toBe('/dashboard');
  });

  it('should use default fallback /', () => {
    const url = restoreAuthRedirect(storage);

    expect(url).toBe('/');
  });

  it('should re-validate on restore', () => {
    // Save without validation
    storage.set('auth_redirect', 'javascript:alert(1)');

    const url = restoreAuthRedirect(storage, { fallback: '/safe' });

    expect(url).toBe('/safe'); // Invalid URL replaced with fallback
  });

  it('should use custom key', () => {
    storage.set('my_redirect', '/custom');

    const url = restoreAuthRedirect(storage, {
      key: 'my_redirect',
      fallback: '/default',
    });

    expect(url).toBe('/custom');
    expect(storage.get('my_redirect')).toBeNull();
  });

  it('should validate with allowed paths', () => {
    saveAuthRedirect('/admin', storage, { validate: false });

    const url = restoreAuthRedirect(storage, {
      allowedPaths: ['/dashboard'],
      fallback: '/dashboard',
    });

    expect(url).toBe('/dashboard'); // /admin not in allowed paths
  });
});

describe('peekAuthRedirect', () => {
  let storage: MemoryRedirectStorage;

  beforeEach(() => {
    storage = new MemoryRedirectStorage();
  });

  it('should return saved redirect without clearing', () => {
    saveAuthRedirect('/profile', storage);

    const url = peekAuthRedirect(storage);

    expect(url).toBe('/profile');
    expect(storage.get('auth_redirect')).toBe('/profile'); // Still there
  });

  it('should return null if no redirect', () => {
    const url = peekAuthRedirect(storage);

    expect(url).toBeNull();
  });

  it('should use custom key', () => {
    storage.set('my_redirect', '/custom');

    const url = peekAuthRedirect(storage, { key: 'my_redirect' });

    expect(url).toBe('/custom');
  });
});

describe('clearAuthRedirect', () => {
  let storage: MemoryRedirectStorage;

  beforeEach(() => {
    storage = new MemoryRedirectStorage();
  });

  it('should clear saved redirect', () => {
    saveAuthRedirect('/profile', storage);

    clearAuthRedirect(storage);

    expect(storage.get('auth_redirect')).toBeNull();
  });

  it('should use custom key', () => {
    storage.set('my_redirect', '/custom');

    clearAuthRedirect(storage, { key: 'my_redirect' });

    expect(storage.get('my_redirect')).toBeNull();
  });

  it('should not error if nothing to clear', () => {
    expect(() => {
      clearAuthRedirect(storage);
    }).not.toThrow();
  });
});

describe('InvalidRedirectError', () => {
  it('should create error with default message', () => {
    const error = new InvalidRedirectError();
    expect(error.message).toBe('Invalid redirect URL');
    expect(error.name).toBe('InvalidRedirectError');
  });

  it('should create error with custom message', () => {
    const error = new InvalidRedirectError('Custom message');
    expect(error.message).toBe('Custom message');
    expect(error.name).toBe('InvalidRedirectError');
  });
});
