/**
 * Session-CSRF Integration Adapter
 * Bridges SessionStorageAdapter with CSRFStorageAdapter
 * Allows storing CSRF tokens within session data
 */

import type { SessionStorageAdapter } from '../../session/storage/storage-adapter';
import type { CSRFStorageAdapter } from '../csrf/storage';

/**
 * Session data structure with CSRF tokens
 */
interface SessionWithCSRF {
  csrf?: Record<string, { token: string; expiresAt?: number }>;
  [key: string]: unknown;
}

/**
 * CSRF storage adapter that stores tokens in session storage
 * Provides integration between session and CSRF modules
 *
 * @example
 * ```typescript
 * import { UniversalMemoryStorage } from '@amtarc/auth-utils/storage';
 * import { SessionCSRFAdapter } from '@amtarc/auth-utils/security/csrf';
 * import { generateSynchronizerToken } from '@amtarc/auth-utils/security/csrf';
 *
 * const sessionStorage = new UniversalMemoryStorage();
 * const session = { id: 'session-123', userId: 'user-1', ... };
 *
 * // Create CSRF adapter that stores in session
 * const csrfStorage = new SessionCSRFAdapter(sessionStorage, session.id);
 *
 * // Generate CSRF token stored in session
 * const { token } = await generateSynchronizerToken({
 *   session,
 *   storage: csrfStorage
 * });
 * ```
 */
export class SessionCSRFAdapter implements CSRFStorageAdapter {
  constructor(
    private sessionStorage: SessionStorageAdapter<SessionWithCSRF>,
    private sessionId: string
  ) {}

  async set(key: string, token: string, ttl?: number): Promise<void> {
    const session = await this.sessionStorage.get(this.sessionId);
    if (!session) {
      throw new Error(`Session not found: ${this.sessionId}`);
    }

    if (!session.csrf) {
      session.csrf = {};
    }

    const expiresAt = ttl ? Date.now() + ttl : undefined;
    if (expiresAt !== undefined) {
      session.csrf[key] = { token, expiresAt };
    } else {
      session.csrf[key] = { token };
    }

    await this.sessionStorage.set(this.sessionId, session);
  }

  async get(key: string): Promise<string | null> {
    const session = await this.sessionStorage.get(this.sessionId);
    if (!session?.csrf) {
      return null;
    }

    const entry = session.csrf[key];
    if (!entry) {
      return null;
    }

    // Check expiration
    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      await this.delete(key);
      return null;
    }

    return entry.token;
  }

  async delete(key: string): Promise<void> {
    const session = await this.sessionStorage.get(this.sessionId);
    if (session?.csrf) {
      delete session.csrf[key];
      await this.sessionStorage.set(this.sessionId, session);
    }
  }

  async exists(key: string): Promise<boolean> {
    const token = await this.get(key);
    return token !== null;
  }

  async has(key: string): Promise<boolean> {
    return this.exists(key);
  }
}
