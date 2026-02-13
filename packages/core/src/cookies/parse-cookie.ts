/**
 * @amtarc/auth-utils - Cookie Parsing
 * Parse HTTP Cookie headers
 */

/**
 * Parse Cookie header into key-value pairs
 *
 * @example
 * ```typescript
 * const cookies = parseAuthCookies(req.headers.cookie);
 * console.log(cookies); // { session: 'abc123', theme: 'dark' }
 * ```
 */
export function parseAuthCookies(
  cookieHeader: string | undefined
): Record<string, string> {
  const cookies: Record<string, string> = {};

  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return cookies;
  }

  cookieHeader.split(';').forEach((cookie) => {
    const separatorIndex = cookie.indexOf('=');

    if (separatorIndex === -1) {
      // No '=' found, skip this cookie
      return;
    }

    const name = cookie.slice(0, separatorIndex).trim();
    const value = cookie.slice(separatorIndex + 1).trim();

    if (name) {
      try {
        cookies[decodeURIComponent(name)] = decodeURIComponent(value);
      } catch {
        // If decoding fails, use the raw value
        cookies[name] = value;
      }
    }
  });

  return cookies;
}

/**
 * Get a specific cookie value from Cookie header
 *
 * @example
 * ```typescript
 * const sessionId = getAuthCookie(req.headers.cookie, 'session');
 * if (sessionId) {
 *   // Session exists
 * }
 * ```
 */
export function getAuthCookie(
  cookieHeader: string | undefined,
  name: string
): string | null {
  const cookies = parseAuthCookies(cookieHeader);
  return cookies[name] ?? null;
}

/**
 * Check if a cookie exists in the Cookie header
 */
export function hasAuthCookie(
  cookieHeader: string | undefined,
  name: string
): boolean {
  return getAuthCookie(cookieHeader, name) !== null;
}

/**
 * Parse Set-Cookie header (from responses)
 * This is more complex as Set-Cookie can have attributes
 */
export interface ParsedCookie {
  name: string;
  value: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  path?: string;
  domain?: string;
  maxAge?: number;
  expires?: Date;
}

/**
 * Parse a single Set-Cookie header value
 *
 * @example
 * ```typescript
 * const parsed = parseSetCookie('session=abc123; HttpOnly; Secure; SameSite=Lax');
 * console.log(parsed.httpOnly); // true
 * ```
 */
export function parseSetCookie(setCookieHeader: string): ParsedCookie | null {
  if (!setCookieHeader) return null;

  const parts = setCookieHeader.split(';').map((p) => p.trim());
  const firstPart = parts[0];
  const separatorIndex = firstPart?.indexOf('=');

  if (!firstPart || separatorIndex === -1 || separatorIndex === undefined) {
    return null;
  }

  const name = firstPart.slice(0, separatorIndex).trim();
  const value = firstPart.slice(separatorIndex + 1).trim();

  let decodedName = name;
  let decodedValue = value;
  try {
    decodedName = decodeURIComponent(name);
  } catch {
    // If decoding fails, fall back to the raw name
  }
  try {
    decodedValue = decodeURIComponent(value);
  } catch {
    // If decoding fails, fall back to the raw value
  }
  const parsed: ParsedCookie = {
    name: decodedName,
    value: decodedValue,
  };

  // Parse attributes
  for (let i = 1; i < parts.length; i++) {
    const attr = parts[i];

    if (!attr) {
      continue;
    }

    const eqIndex = attr.indexOf('=');

    if (eqIndex === -1) {
      // Boolean attribute
      const attrLower = attr.toLowerCase();
      if (attrLower === 'httponly') {
        parsed.httpOnly = true;
      } else if (attrLower === 'secure') {
        parsed.secure = true;
      }
    } else {
      // Key-value attribute
      const key = attr.slice(0, eqIndex).trim().toLowerCase();
      const val = attr.slice(eqIndex + 1).trim();

      switch (key) {
        case 'path':
          parsed.path = val;
          break;
        case 'domain':
          parsed.domain = val;
          break;
        case 'max-age':
          parsed.maxAge = parseInt(val, 10);
          break;
        case 'expires':
          parsed.expires = new Date(val);
          break;
        case 'samesite': {
          const sameSite = val.toLowerCase();
          if (
            sameSite === 'strict' ||
            sameSite === 'lax' ||
            sameSite === 'none'
          ) {
            parsed.sameSite = sameSite;
          }
          break;
        }
      }
    }
  }

  return parsed;
}
