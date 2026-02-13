/**
 * Content Security Policy (CSP) Builder
 * Type-safe CSP policy generation
 */

export interface CSPDirectives {
  'default-src'?: string[];
  'script-src'?: string[];
  'script-src-elem'?: string[];
  'script-src-attr'?: string[];
  'style-src'?: string[];
  'style-src-elem'?: string[];
  'style-src-attr'?: string[];
  'img-src'?: string[];
  'font-src'?: string[];
  'connect-src'?: string[];
  'media-src'?: string[];
  'object-src'?: string[];
  'frame-src'?: string[];
  'child-src'?: string[];
  'form-action'?: string[];
  'frame-ancestors'?: string[];
  'base-uri'?: string[];
  'manifest-src'?: string[];
  'worker-src'?: string[];
  'prefetch-src'?: string[];
  'navigate-to'?: string[];
  'report-uri'?: string[];
  'report-to'?: string[];
  'require-trusted-types-for'?: string[];
  'trusted-types'?: string[];
  'upgrade-insecure-requests'?: boolean;
  'block-all-mixed-content'?: boolean;
  sandbox?: string[];
}

export interface CSPOptions {
  directives?: CSPDirectives;
  reportOnly?: boolean;
}

export class CSPBuilder {
  private directives: CSPDirectives = {};
  private reportOnly = false;

  constructor(options: CSPOptions = {}) {
    if (options.directives) {
      this.directives = { ...options.directives };
    }
    this.reportOnly = options.reportOnly || false;
  }

  /**
   * Set default source
   */
  defaultSrc(...sources: string[]): this {
    this.directives['default-src'] = sources;
    return this;
  }

  /**
   * Set script source
   */
  scriptSrc(...sources: string[]): this {
    this.directives['script-src'] = sources;
    return this;
  }

  /**
   * Set style source
   */
  styleSrc(...sources: string[]): this {
    this.directives['style-src'] = sources;
    return this;
  }

  /**
   * Set image source
   */
  imgSrc(...sources: string[]): this {
    this.directives['img-src'] = sources;
    return this;
  }

  /**
   * Set font source
   */
  fontSrc(...sources: string[]): this {
    this.directives['font-src'] = sources;
    return this;
  }

  /**
   * Set connect source
   */
  connectSrc(...sources: string[]): this {
    this.directives['connect-src'] = sources;
    return this;
  }

  /**
   * Set frame source
   */
  frameSrc(...sources: string[]): this {
    this.directives['frame-src'] = sources;
    return this;
  }

  /**
   * Set frame ancestors
   */
  frameAncestors(...sources: string[]): this {
    this.directives['frame-ancestors'] = sources;
    return this;
  }

  /**
   * Set form action
   */
  formAction(...sources: string[]): this {
    this.directives['form-action'] = sources;
    return this;
  }

  /**
   * Set base URI
   */
  baseUri(...sources: string[]): this {
    this.directives['base-uri'] = sources;
    return this;
  }

  /**
   * Set object source
   */
  objectSrc(...sources: string[]): this {
    this.directives['object-src'] = sources;
    return this;
  }

  /**
   * Set media source
   */
  mediaSrc(...sources: string[]): this {
    this.directives['media-src'] = sources;
    return this;
  }

  /**
   * Set worker source
   */
  workerSrc(...sources: string[]): this {
    this.directives['worker-src'] = sources;
    return this;
  }

  /**
   * Set manifest source
   */
  manifestSrc(...sources: string[]): this {
    this.directives['manifest-src'] = sources;
    return this;
  }

  /**
   * Set report URI
   */
  reportUri(...uris: string[]): this {
    this.directives['report-uri'] = uris;
    return this;
  }

  /**
   * Set report-to endpoint
   */
  reportTo(...groups: string[]): this {
    this.directives['report-to'] = groups;
    return this;
  }

  /**
   * Upgrade insecure requests
   */
  upgradeInsecureRequests(): this {
    this.directives['upgrade-insecure-requests'] = true;
    return this;
  }

  /**
   * Block all mixed content
   */
  blockAllMixedContent(): this {
    this.directives['block-all-mixed-content'] = true;
    return this;
  }

  /**
   * Set sandbox
   */
  sandbox(...values: string[]): this {
    this.directives.sandbox = values;
    return this;
  }

  /**
   * Require trusted types for scripts
   */
  requireTrustedTypesFor(...values: string[]): this {
    this.directives['require-trusted-types-for'] = values;
    return this;
  }

  /**
   * Set trusted types policy
   */
  trustedTypes(...policies: string[]): this {
    this.directives['trusted-types'] = policies;
    return this;
  }

  /**
   * Build CSP header value
   */
  build(): string {
    const directives: string[] = [];

    for (const [key, value] of Object.entries(this.directives)) {
      if (value === true) {
        directives.push(key);
      } else if (Array.isArray(value) && value.length > 0) {
        directives.push(`${key} ${value.join(' ')}`);
      }
    }

    return directives.join('; ');
  }

  /**
   * Get header name
   */
  getHeaderName(): string {
    return this.reportOnly
      ? 'Content-Security-Policy-Report-Only'
      : 'Content-Security-Policy';
  }

  /**
   * Get as header object
   */
  toHeader(): Record<string, string> {
    return {
      [this.getHeaderName()]: this.build(),
    };
  }

  /**
   * Create strict CSP policy
   */
  static strict(): CSPBuilder {
    return new CSPBuilder()
      .defaultSrc("'none'")
      .scriptSrc("'self'")
      .styleSrc("'self'")
      .imgSrc("'self'", 'data:')
      .fontSrc("'self'")
      .connectSrc("'self'")
      .frameSrc("'none'")
      .objectSrc("'none'")
      .baseUri("'self'")
      .formAction("'self'")
      .frameAncestors("'none'")
      .upgradeInsecureRequests();
  }

  /**
   * Create relaxed CSP policy (for development)
   */
  static relaxed(): CSPBuilder {
    return new CSPBuilder()
      .defaultSrc("'self'")
      .scriptSrc("'self'", "'unsafe-inline'", "'unsafe-eval'")
      .styleSrc("'self'", "'unsafe-inline'")
      .imgSrc("'self'", 'data:', 'blob:')
      .fontSrc("'self'", 'data:')
      .connectSrc("'self'")
      .upgradeInsecureRequests();
  }
}
