/**
 * CSRF protection type definitions
 */

import type { CSRFStorageAdapter } from './storage';
import type { Session } from '../../types';
import type { RequestContext, ResponseContext } from '../../types';

export interface CSRFProtectionOptions {
  /** CSRF protection pattern */
  pattern: 'double-submit' | 'synchronizer';

  /** Methods to protect (default: ['POST', 'PUT', 'DELETE', 'PATCH']) */
  methods?: string[];

  /** Paths to exempt from CSRF protection */
  exemptPaths?: string[] | RegExp[];

  /** Storage adapter (required for synchronizer pattern) */
  storage?: CSRFStorageAdapter;

  /** Cookie options (for double-submit) */
  cookieName?: string;
  cookieOptions?: {
    secure?: boolean;
    sameSite?: 'strict' | 'lax' | 'none';
    httpOnly?: boolean;
    path?: string;
    domain?: string;
  };

  /** Header/field names */
  headerName?: string;
  fieldName?: string;

  /** Strict mode: throw on validation failure */
  strict?: boolean;

  /** Custom error handler */
  onError?: (
    error: Error,
    context: CSRFMiddlewareContext
  ) => void | Promise<void>;

  /** Token regeneration strategy (synchronizer only) */
  regenerate?: 'per-request' | 'per-session' | 'never';

  /** Token lifetime in ms */
  lifetime?: number;
}

export interface CSRFMiddlewareContext {
  request: RequestContext;
  response: ResponseContext;
  session?: Session;
}

export type CSRFMiddleware = (
  context: CSRFMiddlewareContext,
  next?: () => Promise<void>
) => Promise<void>;
