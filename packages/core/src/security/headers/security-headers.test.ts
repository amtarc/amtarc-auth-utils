/**
 * Security Headers Builder Tests
 */

import { describe, it, expect } from 'vitest';
import { CSPBuilder } from './csp/builder';
import {
  SecurityHeadersBuilder,
  createSecurityHeaders,
} from './security-headers';

describe('SecurityHeadersBuilder', () => {
  it('should create headers with CSP', () => {
    const csp = new CSPBuilder().defaultSrc("'self'");
    const headers = new SecurityHeadersBuilder({ csp }).getHeaders();

    expect(headers['Content-Security-Policy']).toBeDefined();
  });

  it('should create HSTS header', () => {
    const headers = new SecurityHeadersBuilder({
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
    }).getHeaders();

    expect(headers['Strict-Transport-Security']).toBe(
      'max-age=31536000; includeSubDomains; preload'
    );
  });

  it('should create X-Frame-Options header', () => {
    let headers = new SecurityHeadersBuilder({
      frameOptions: 'DENY',
    }).getHeaders();
    expect(headers['X-Frame-Options']).toBe('DENY');

    headers = new SecurityHeadersBuilder({
      frameOptions: 'SAMEORIGIN',
    }).getHeaders();
    expect(headers['X-Frame-Options']).toBe('SAMEORIGIN');
  });

  it('should create X-Content-Type-Options header', () => {
    const headers = new SecurityHeadersBuilder({
      contentTypeOptions: true,
    }).getHeaders();

    expect(headers['X-Content-Type-Options']).toBe('nosniff');
  });

  it('should create X-XSS-Protection header', () => {
    let headers = new SecurityHeadersBuilder({
      xssProtection: true,
    }).getHeaders();
    expect(headers['X-XSS-Protection']).toBe('1; mode=block');

    headers = new SecurityHeadersBuilder({
      xssProtection: false,
    }).getHeaders();
    expect(headers['X-XSS-Protection']).toBe('0');

    headers = new SecurityHeadersBuilder({
      xssProtection: { mode: 'block' },
    }).getHeaders();
    expect(headers['X-XSS-Protection']).toBe('1; mode=block');
  });

  it('should create Referrer-Policy header', () => {
    const headers = new SecurityHeadersBuilder({
      referrerPolicy: 'strict-origin-when-cross-origin',
    }).getHeaders();

    expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
  });

  it('should create Permissions-Policy header', () => {
    const headers = new SecurityHeadersBuilder({
      permissionsPolicy: {
        camera: [],
        microphone: ["'self'"],
        geolocation: ["'self'", 'https://example.com'],
      },
    }).getHeaders();

    const policy = headers['Permissions-Policy'];
    expect(policy).toContain('camera=()');
    expect(policy).toContain("microphone=('self')");
    expect(policy).toContain("geolocation=('self' https://example.com)");
  });

  it('should create COEP header', () => {
    const headers = new SecurityHeadersBuilder({
      crossOriginEmbedderPolicy: 'require-corp',
    }).getHeaders();

    expect(headers['Cross-Origin-Embedder-Policy']).toBe('require-corp');
  });

  it('should create COOP header', () => {
    const headers = new SecurityHeadersBuilder({
      crossOriginOpenerPolicy: 'same-origin',
    }).getHeaders();

    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
  });

  it('should create CORP header', () => {
    const headers = new SecurityHeadersBuilder({
      crossOriginResourcePolicy: 'same-origin',
    }).getHeaders();

    expect(headers['Cross-Origin-Resource-Policy']).toBe('same-origin');
  });

  it('should create secure default headers', () => {
    const headers = SecurityHeadersBuilder.secure().getHeaders();

    expect(headers['Content-Security-Policy']).toBeDefined();
    expect(headers['Strict-Transport-Security']).toBeDefined();
    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
    expect(headers['Referrer-Policy']).toBe('strict-origin-when-cross-origin');
    expect(headers['Cross-Origin-Embedder-Policy']).toBe('require-corp');
    expect(headers['Cross-Origin-Opener-Policy']).toBe('same-origin');
  });

  it('should create relaxed headers', () => {
    const headers = SecurityHeadersBuilder.relaxed().getHeaders();

    expect(headers['Content-Security-Policy']).toBeDefined();
    expect(headers['X-Frame-Options']).toBe('SAMEORIGIN');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
  });

  it('should allow adding custom headers', () => {
    const builder = new SecurityHeadersBuilder().addHeader(
      'X-Custom-Header',
      'custom-value'
    );

    const headers = builder.getHeaders();
    expect(headers['X-Custom-Header']).toBe('custom-value');
  });

  it('should allow removing headers', () => {
    const builder = new SecurityHeadersBuilder({
      contentTypeOptions: true,
    }).removeHeader('X-Content-Type-Options');

    const headers = builder.getHeaders();
    expect(headers['X-Content-Type-Options']).toBeUndefined();
  });
});

describe('createSecurityHeaders', () => {
  it('should create security headers', () => {
    const headers = createSecurityHeaders({
      frameOptions: 'DENY',
      contentTypeOptions: true,
    });

    expect(headers['X-Frame-Options']).toBe('DENY');
    expect(headers['X-Content-Type-Options']).toBe('nosniff');
  });

  it('should work with no options', () => {
    const headers = createSecurityHeaders();
    expect(headers).toBeDefined();
    expect(typeof headers).toBe('object');
  });
});
