/**
 * Synchronizer token CSRF protection pattern
 *
 * This pattern stores the CSRF token on the server (in session)
 * and validates it against the submitted token. More secure than
 * double-submit but requires server-side state.
 */

import { generateCSRFToken } from './generate-token';
import { validateCSRFToken } from './validate-token';
import type { CSRFStorageAdapter } from './storage';
import type { Session } from '../../types';

export interface SynchronizerTokenOptions {
  /** Session to store token in */
  session: Session;
  /** Storage adapter */
  storage: CSRFStorageAdapter;
  /** Token regeneration strategy */
  regenerate?: 'per-request' | 'per-session' | 'never';
  /** Token lifetime in ms */
  lifetime?: number;
}

export interface SynchronizerTokenResult {
  token: string;
  sessionUpdated: boolean;
}

/**
 * Generate synchronizer CSRF token
 * Stores token in session and returns it
 */
export async function generateSynchronizerToken(
  options: SynchronizerTokenOptions
): Promise<SynchronizerTokenResult> {
  const {
    session,
    storage,
    regenerate = 'per-session',
    lifetime = 3600000,
  } = options;

  const key = `csrf:${session.id}`;

  // Check if token exists and regeneration strategy
  if (regenerate === 'never' || regenerate === 'per-session') {
    const existingToken = await storage.get(key);
    if (existingToken) {
      return { token: existingToken, sessionUpdated: false };
    }
  }

  // Generate new token
  const token = generateCSRFToken({
    length: 32,
    includeTimestamp: true,
    lifetime,
  });

  // Store in session storage with TTL (duration in ms)
  await storage.set(key, token, lifetime);

  return { token, sessionUpdated: true };
}

/**
 * Validate synchronizer CSRF token
 */
export async function validateSynchronizerToken(
  token: string,
  options: {
    session: Session;
    storage: CSRFStorageAdapter;
    deleteAfterUse?: boolean;
    strict?: boolean;
  }
): Promise<{ valid: boolean; reason?: string }> {
  const { session, storage, deleteAfterUse = false, strict = false } = options;

  const key = `csrf:${session.id}`;

  try {
    const result = await validateCSRFToken(token, {
      storage,
      key,
      deleteAfterUse,
      strict,
    });

    return result;
  } catch (error) {
    if (strict) {
      throw error;
    }
    return { valid: false, reason: 'invalid' };
  }
}

/**
 * Escape HTML attribute value
 */
function escapeAttribute(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Attach CSRF token to response
 * Helper to set token in meta tag or hidden form field
 */
export function attachCSRFTokenToHTML(
  token: string,
  options: { method?: 'meta' | 'input'; name?: string } = {}
): string {
  const { method = 'meta', name = 'csrf-token' } = options;

  // Escape to prevent XSS via quote-breaking
  const escapedName = escapeAttribute(name);
  const escapedToken = escapeAttribute(token);

  if (method === 'meta') {
    return `<meta name="${escapedName}" content="${escapedToken}">`;
  } else {
    return `<input type="hidden" name="${escapedName}" value="${escapedToken}">`;
  }
}
