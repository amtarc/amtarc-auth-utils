/**
 * Security headers builder
 * Collection of security-related HTTP headers
 */

import { CSPBuilder } from './csp/builder';

export interface SecurityHeadersOptions {
  csp?: CSPBuilder | string;
  hsts?: {
    maxAge?: number;
    includeSubDomains?: boolean;
    preload?: boolean;
  };
  frameOptions?: 'DENY' | 'SAMEORIGIN' | string;
  contentTypeOptions?: boolean;
  xssProtection?: boolean | { mode: 'block' | 'sanitize'; report?: string };
  referrerPolicy?:
    | 'no-referrer'
    | 'no-referrer-when-downgrade'
    | 'origin'
    | 'origin-when-cross-origin'
    | 'same-origin'
    | 'strict-origin'
    | 'strict-origin-when-cross-origin'
    | 'unsafe-url';
  permissionsPolicy?: Record<string, string[]>;
  crossOriginEmbedderPolicy?: 'require-corp' | 'credentialless' | 'unsafe-none';
  crossOriginOpenerPolicy?:
    | 'same-origin'
    | 'same-origin-allow-popups'
    | 'unsafe-none';
  crossOriginResourcePolicy?: 'same-site' | 'same-origin' | 'cross-origin';
}

export class SecurityHeadersBuilder {
  private headers: Record<string, string> = {};

  constructor(private options: SecurityHeadersOptions = {}) {
    this.applyDefaults();
  }

  private applyDefaults(): void {
    // Content Security Policy
    if (this.options.csp) {
      if (typeof this.options.csp === 'string') {
        this.headers['Content-Security-Policy'] = this.options.csp;
      } else {
        Object.assign(this.headers, this.options.csp.toHeader());
      }
    }

    // HSTS (HTTP Strict Transport Security)
    if (this.options.hsts !== undefined) {
      const hsts = this.options.hsts;
      const maxAge = hsts.maxAge || 31536000; // 1 year default
      let hstsValue = `max-age=${maxAge}`;

      if (hsts.includeSubDomains) {
        hstsValue += '; includeSubDomains';
      }
      if (hsts.preload) {
        hstsValue += '; preload';
      }

      this.headers['Strict-Transport-Security'] = hstsValue;
    }

    // X-Frame-Options
    if (this.options.frameOptions !== undefined) {
      this.headers['X-Frame-Options'] = this.options.frameOptions;
    }

    // X-Content-Type-Options
    if (this.options.contentTypeOptions) {
      this.headers['X-Content-Type-Options'] = 'nosniff';
    }

    // X-XSS-Protection (deprecated but still useful for older browsers)
    if (this.options.xssProtection !== undefined) {
      if (typeof this.options.xssProtection === 'boolean') {
        this.headers['X-XSS-Protection'] = this.options.xssProtection
          ? '1; mode=block'
          : '0';
      } else {
        let value = '1';
        if (this.options.xssProtection.mode === 'block') {
          value += '; mode=block';
        }
        if (this.options.xssProtection.report) {
          value += `; report=${this.options.xssProtection.report}`;
        }
        this.headers['X-XSS-Protection'] = value;
      }
    }

    // Referrer-Policy
    if (this.options.referrerPolicy) {
      this.headers['Referrer-Policy'] = this.options.referrerPolicy;
    }

    // Permissions-Policy (formerly Feature-Policy)
    if (this.options.permissionsPolicy) {
      const policies = Object.entries(this.options.permissionsPolicy)
        .map(([feature, allowlist]) => {
          if (allowlist.length === 0) {
            return `${feature}=()`;
          }
          return `${feature}=(${allowlist.join(' ')})`;
        })
        .join(', ');

      this.headers['Permissions-Policy'] = policies;
    }

    // COEP (Cross-Origin-Embedder-Policy)
    if (this.options.crossOriginEmbedderPolicy) {
      this.headers['Cross-Origin-Embedder-Policy'] =
        this.options.crossOriginEmbedderPolicy;
    }

    // COOP (Cross-Origin-Opener-Policy)
    if (this.options.crossOriginOpenerPolicy) {
      this.headers['Cross-Origin-Opener-Policy'] =
        this.options.crossOriginOpenerPolicy;
    }

    // CORP (Cross-Origin-Resource-Policy)
    if (this.options.crossOriginResourcePolicy) {
      this.headers['Cross-Origin-Resource-Policy'] =
        this.options.crossOriginResourcePolicy;
    }
  }

  /**
   * Get all headers
   */
  getHeaders(): Record<string, string> {
    return { ...this.headers };
  }

  /**
   * Add custom header
   */
  addHeader(name: string, value: string): this {
    this.headers[name] = value;
    return this;
  }

  /**
   * Remove header
   */
  removeHeader(name: string): this {
    delete this.headers[name];
    return this;
  }

  /**
   * Create secure default headers
   */
  static secure(): SecurityHeadersBuilder {
    return new SecurityHeadersBuilder({
      csp: CSPBuilder.strict(),
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      frameOptions: 'DENY',
      contentTypeOptions: true,
      xssProtection: { mode: 'block' },
      referrerPolicy: 'strict-origin-when-cross-origin',
      crossOriginEmbedderPolicy: 'require-corp',
      crossOriginOpenerPolicy: 'same-origin',
      crossOriginResourcePolicy: 'same-origin',
      permissionsPolicy: {
        camera: [],
        microphone: [],
        geolocation: [],
        payment: [],
      },
    });
  }

  /**
   * Create relaxed headers (for development)
   */
  static relaxed(): SecurityHeadersBuilder {
    return new SecurityHeadersBuilder({
      csp: CSPBuilder.relaxed(),
      frameOptions: 'SAMEORIGIN',
      contentTypeOptions: true,
      xssProtection: true,
      referrerPolicy: 'no-referrer-when-downgrade',
    });
  }
}

/**
 * Convenience function to create security headers
 */
export function createSecurityHeaders(
  options?: SecurityHeadersOptions
): Record<string, string> {
  return new SecurityHeadersBuilder(options).getHeaders();
}
