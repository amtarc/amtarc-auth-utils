/**
 * Core type definitions for @amtarc/auth-utils
 */

/**
 * Base user type - meant to be extended by consumers
 */
export interface User {
  id: string;
  [key: string]: unknown;
}

/**
 * Session data structure
 */
export interface Session<TUser extends User = User> {
  id: string;
  userId: string;
  user?: TUser;
  expiresAt: Date;
  createdAt: Date;
  lastActiveAt: Date;
  metadata?: Record<string, unknown>;
  fingerprint?: string;
}

/**
 * Session options
 */
export interface SessionOptions {
  /** Session expiration time in milliseconds */
  expiresIn?: number;
  /** Idle timeout in milliseconds */
  idleTimeout?: number;
  /** Absolute timeout in milliseconds */
  absoluteTimeout?: number;
  /** Enable session fingerprinting */
  fingerprint?: boolean;
}

/**
 * Cookie options
 */
export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: 'strict' | 'lax' | 'none';
  domain?: string;
  path?: string;
  maxAge?: number;
  expires?: Date;
  signed?: boolean;
  encrypted?: boolean;
}

/**
 * Request context (framework-agnostic)
 */
export interface RequestContext {
  headers: Record<string, string | string[] | undefined>;
  cookies: Record<string, string>;
  url: string;
  method: string;
  ip?: string;
}

/**
 * Response context (framework-agnostic)
 */
export interface ResponseContext {
  setHeader(_name: string, _value: string): void;
  setCookie(_name: string, _value: string, _options?: CookieOptions): void;
  redirect?(_url: string, _status?: number): void;
}
