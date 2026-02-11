/**
 * @amtarc/auth-utils - Session Fingerprinting
 * Generate and validate session fingerprints for enhanced security
 */

import { createHash } from 'node:crypto';
import type { Session } from '../types';
import { FingerprintMismatchError } from '../errors';

/**
 * Metadata used to generate session fingerprint
 */
export interface FingerprintMetadata {
  /** User-Agent header */
  userAgent?: string;
  /** Client IP address */
  ip?: string;
  /** Accept-Language header */
  acceptLanguage?: string;
  /** Platform/OS information */
  platform?: string;
  /** Additional custom fields */
  [key: string]: string | undefined;
}

/**
 * Options for fingerprint validation
 */
export interface FingerprintValidationOptions {
  /**
   * Strict mode - throw error on mismatch
   * @default false
   */
  strict?: boolean;

  /**
   * Allow sessions without fingerprints
   * @default true
   */
  allowMissing?: boolean;

  /**
   * Custom error message
   */
  message?: string;
}

/**
 * Generate a session fingerprint from request metadata
 *
 * Uses SHA-256 hash of:
 * - User-Agent
 * - IP address
 * - Accept-Language
 * - Platform
 *
 * @example
 * ```typescript
 * const fingerprint = generateSessionFingerprint({
 *   userAgent: req.headers['user-agent'],
 *   ip: req.ip,
 *   acceptLanguage: req.headers['accept-language']
 * });
 * ```
 *
 * @warning Fingerprints can change legitimately (VPN, proxy, browser updates)
 * Use with care and provide good error messages to users
 */
export function generateSessionFingerprint(
  metadata: FingerprintMetadata
): string {
  // Normalize and concatenate components
  const components = [
    normalizeUserAgent(metadata.userAgent || ''),
    normalizeIp(metadata.ip || ''),
    metadata.acceptLanguage || '',
    metadata.platform || '',
  ];

  // Create SHA-256 hash
  return createHash('sha256').update(components.join('|')).digest('hex');
}

/**
 * Validate session fingerprint against current request metadata
 *
 * @example
 * ```typescript
 * const isValid = validateFingerprint(session, {
 *   userAgent: req.headers['user-agent'],
 *   ip: req.ip
 * });
 *
 * if (!isValid) {
 *   // Handle potential session hijacking
 * }
 * ```
 *
 * @example With strict mode
 * ```typescript
 * try {
 *   validateFingerprint(session, metadata, { strict: true });
 * } catch (err) {
 *   if (err instanceof FingerprintMismatchError) {
 *     // Log security incident
 *     // Invalidate session
 *   }
 * }
 * ```
 */
export function validateFingerprint(
  session: Session,
  currentMetadata: FingerprintMetadata,
  options?: FingerprintValidationOptions
): boolean {
  // No fingerprint stored
  if (!session.fingerprint) {
    const allowMissing = options?.allowMissing ?? true;
    if (!allowMissing && options?.strict) {
      throw new FingerprintMismatchError(
        options?.message || 'Session has no fingerprint'
      );
    }
    return allowMissing;
  }

  const currentFingerprint = generateSessionFingerprint(currentMetadata);

  // Fingerprint mismatch
  if (session.fingerprint !== currentFingerprint) {
    if (options?.strict) {
      throw new FingerprintMismatchError(options?.message);
    }
    return false;
  }

  return true;
}

/**
 * Compare two fingerprints for equality
 *
 * @example
 * ```typescript
 * const matches = compareFingerprints(
 *   session.fingerprint,
 *   newFingerprint
 * );
 * ```
 */
export function compareFingerprints(
  fingerprint1: string | undefined,
  fingerprint2: string | undefined
): boolean {
  if (!fingerprint1 || !fingerprint2) {
    return false;
  }

  // Constant-time comparison to prevent timing attacks
  // Though for fingerprints this is probably overkill, good practice
  if (fingerprint1.length !== fingerprint2.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < fingerprint1.length; i++) {
    result |= fingerprint1.charCodeAt(i) ^ fingerprint2.charCodeAt(i);
  }

  return result === 0;
}

/**
 * Extract fingerprint metadata from an HTTP request
 *
 * Helper to extract common fingerprint sources from request objects
 *
 * @example
 * ```typescript
 * // Express
 * const metadata = extractFingerprintMetadata(req);
 *
 * // Next.js
 * const metadata = extractFingerprintMetadata(req, {
 *   ip: req.headers['x-forwarded-for'] || req.ip
 * });
 * ```
 */
export function extractFingerprintMetadata(
  request: {
    headers?: Record<string, string | string[] | undefined>;
    ip?: string;
  },
  overrides?: Partial<FingerprintMetadata>
): FingerprintMetadata {
  const headers = request.headers || {};

  const userAgent = getHeader(headers, 'user-agent');
  const acceptLanguage = getHeader(headers, 'accept-language');
  const platform = getHeader(headers, 'sec-ch-ua-platform');
  const ip = overrides?.ip || request.ip;

  const metadata: FingerprintMetadata = {
    ...overrides,
  };

  if (userAgent) metadata.userAgent = userAgent;
  if (ip) metadata.ip = ip;
  if (acceptLanguage) metadata.acceptLanguage = acceptLanguage;
  if (platform) metadata.platform = platform;

  return metadata;
}

/**
 * Normalize User-Agent for fingerprinting
 * Removes version numbers that change frequently
 */
function normalizeUserAgent(userAgent: string): string {
  if (!userAgent) return '';

  // Remove version numbers while keeping browser name
  return userAgent
    .replace(/\d+\.\d+(\.\d+)?/g, '') // Remove version numbers
    .replace(/\s+/g, ' ') // Normalize whitespace
    .trim()
    .toLowerCase();
}

/**
 * Normalize IP address
 * Handles IPv4 and IPv6
 */
function normalizeIp(ip: string): string {
  if (!ip) return '';

  // For IPv6, normalize to canonical form
  // For IPv4, just trim
  return ip.trim().toLowerCase();
}

/**
 * Get header value (handles string or string[] and case-insensitive)
 */
function getHeader(
  headers: Record<string, string | string[] | undefined>,
  name: string
): string | undefined {
  // Try exact match first
  let value = headers[name];

  // If not found, try case-insensitive search
  if (!value) {
    const lowerName = name.toLowerCase();
    const key = Object.keys(headers).find((k) => k.toLowerCase() === lowerName);
    if (key) {
      value = headers[key];
    }
  }

  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}
