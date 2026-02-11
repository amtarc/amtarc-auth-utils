/**
 * @amtarc/auth-utils - Redirect Management
 * Utilities for managing authentication redirects securely
 */

import { InvalidRedirectError } from '../errors';

/**
 * Storage interface for redirect URLs
 */
export interface RedirectStorage {
  set(key: string, value: string, options?: { maxAge?: number }): void;
  get(key: string): string | null;
  delete(key: string): void;
}

/**
 * Options for redirect validation
 */
export interface RedirectValidationOptions {
  /**
   * Allowed hostnames for redirects
   * If not provided, only relative URLs are allowed
   */
  allowedHosts?: string[];

  /**
   * Allowed path patterns
   */
  allowedPaths?: (string | RegExp)[];

  /**
   * Allow external URLs (different host)
   * @default false
   */
  allowExternal?: boolean;
}

/**
 * Options for saving redirects
 */
export interface SaveRedirectOptions extends RedirectValidationOptions {
  /**
   * Storage key for the redirect URL
   * @default 'auth_redirect'
   */
  key?: string;

  /**
   * Maximum age in seconds
   * @default 300 (5 minutes)
   */
  maxAge?: number;

  /**
   * Whether to validate the URL before saving
   * @default true
   */
  validate?: boolean;
}

/**
 * Options for restoring redirects
 */
export interface RestoreRedirectOptions extends RedirectValidationOptions {
  /**
   * Storage key for the redirect URL
   * @default 'auth_redirect'
   */
  key?: string;

  /**
   * Fallback URL if no redirect is stored or validation fails
   * @default '/'
   */
  fallback?: string;
}

/**
 * Validate redirect URL for security
 * Prevents open redirect vulnerabilities
 *
 * @example
 * ```typescript
 * // Only allow relative URLs
 * isValidRedirect('/dashboard'); // true
 * isValidRedirect('https://evil.com'); // false
 *
 * // Allow specific hosts
 * isValidRedirect('https://app.example.com/dashboard', {
 *   allowedHosts: ['app.example.com']
 * }); // true
 * ```
 */
export function isValidRedirect(
  url: string,
  options?: RedirectValidationOptions
): boolean {
  try {
    // Empty or just whitespace
    if (!url || !url.trim()) {
      return false;
    }

    // Check for javascript: protocol and other dangerous schemes
    const dangerousProtocols = ['javascript:', 'data:', 'vbscript:', 'file:'];
    const lowerUrl = url.toLowerCase().trim();

    for (const protocol of dangerousProtocols) {
      if (lowerUrl.startsWith(protocol)) {
        return false;
      }
    }

    // Relative URL (starts with /)
    if (url.startsWith('/') && !url.startsWith('//')) {
      // Check allowed paths
      if (options?.allowedPaths) {
        return options.allowedPaths.some((pattern) => {
          if (typeof pattern === 'string') {
            return url.startsWith(pattern);
          }
          return pattern.test(url);
        });
      }
      return true;
    }

    // Absolute URL - parse it
    // eslint-disable-next-line no-undef
    const parsed = new URL(url);

    // Only allow http/https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return false;
    }

    // External URLs not allowed by default
    if (!options?.allowExternal && !options?.allowedHosts) {
      return false;
    }

    // Check allowed hosts
    if (options?.allowedHosts) {
      const hostname = parsed.hostname;
      const isAllowed = options.allowedHosts.some((allowed) => {
        // Exact match
        if (hostname === allowed) return true;
        // Wildcard subdomain match (*.example.com)
        if (allowed.startsWith('*.')) {
          const domain = allowed.slice(2);
          return hostname.endsWith(`.${domain}`) || hostname === domain;
        }
        return false;
      });

      if (!isAllowed) {
        return false;
      }
    }

    // Check allowed paths
    if (options?.allowedPaths) {
      const matches = options.allowedPaths.some((pattern) => {
        if (typeof pattern === 'string') {
          return parsed.pathname.startsWith(pattern);
        }
        return pattern.test(parsed.pathname);
      });

      if (!matches) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

/**
 * Save the intended redirect URL before authentication
 *
 * @example
 * ```typescript
 * // Before redirecting to login
 * saveAuthRedirect('/protected/page', storage, {
 *   maxAge: 600, // 10 minutes
 *   allowedPaths: ['/protected']
 * });
 * ```
 */
export function saveAuthRedirect(
  url: string,
  storage: RedirectStorage,
  options?: SaveRedirectOptions
): void {
  // Validate by default
  if (options?.validate !== false) {
    if (!isValidRedirect(url, options)) {
      throw new InvalidRedirectError(
        'Unsafe redirect URL - potential open redirect vulnerability'
      );
    }
  }

  storage.set(options?.key || 'auth_redirect', url, {
    maxAge: options?.maxAge || 300, // 5 minutes default
  });
}

/**
 * Restore and clear the saved redirect URL
 *
 * @example
 * ```typescript
 * // After successful login
 * const redirectUrl = restoreAuthRedirect(storage, {
 *   fallback: '/dashboard'
 * });
 *
 * return redirect(redirectUrl); // Redirect to intended page or fallback
 * ```
 */
export function restoreAuthRedirect(
  storage: RedirectStorage,
  options?: RestoreRedirectOptions
): string {
  const url = storage.get(options?.key || 'auth_redirect');

  if (url) {
    storage.delete(options?.key || 'auth_redirect');

    // Re-validate on restore for security
    if (isValidRedirect(url, options)) {
      return url;
    }

    // URL failed validation - use fallback
  }

  return options?.fallback || '/';
}

/**
 * Get the saved redirect URL without clearing it
 * Useful for preview or conditional logic
 */
export function peekAuthRedirect(
  storage: RedirectStorage,
  options?: { key?: string }
): string | null {
  return storage.get(options?.key || 'auth_redirect');
}

/**
 * Clear the saved redirect URL
 */
export function clearAuthRedirect(
  storage: RedirectStorage,
  options?: { key?: string }
): void {
  storage.delete(options?.key || 'auth_redirect');
}
