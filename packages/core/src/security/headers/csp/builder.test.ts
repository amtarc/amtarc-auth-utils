/**
 * CSP Builder Tests
 */

import { describe, it, expect } from 'vitest';
import { CSPBuilder } from './builder';

describe('CSPBuilder', () => {
  it('should build basic CSP policy', () => {
    const csp = new CSPBuilder()
      .defaultSrc("'self'")
      .scriptSrc("'self'", "'unsafe-inline'")
      .build();

    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self' 'unsafe-inline'");
  });

  it('should support all CSP directives', () => {
    const csp = new CSPBuilder()
      .defaultSrc("'self'")
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
      .build();

    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("img-src 'self' data:");
    expect(csp).toContain("frame-src 'none'");
  });

  it('should support boolean directives', () => {
    const csp = new CSPBuilder()
      .upgradeInsecureRequests()
      .blockAllMixedContent()
      .build();

    expect(csp).toContain('upgrade-insecure-requests');
    expect(csp).toContain('block-all-mixed-content');
  });

  it('should support report directives', () => {
    const csp = new CSPBuilder()
      .reportUri('/csp-report')
      .reportTo('csp-endpoint')
      .build();

    expect(csp).toContain('report-uri /csp-report');
    expect(csp).toContain('report-to csp-endpoint');
  });

  it('should support sandbox directive', () => {
    const csp = new CSPBuilder()
      .sandbox('allow-forms', 'allow-scripts')
      .build();

    expect(csp).toContain('sandbox allow-forms allow-scripts');
  });

  it('should create strict policy', () => {
    const csp = CSPBuilder.strict().build();

    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain('upgrade-insecure-requests');
  });

  it('should create relaxed policy', () => {
    const csp = CSPBuilder.relaxed().build();

    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("'unsafe-inline'");
    expect(csp).toContain('upgrade-insecure-requests');
  });

  it('should return correct header name', () => {
    const csp = new CSPBuilder();
    expect(csp.getHeaderName()).toBe('Content-Security-Policy');

    const cspReportOnly = new CSPBuilder({ reportOnly: true });
    expect(cspReportOnly.getHeaderName()).toBe(
      'Content-Security-Policy-Report-Only'
    );
  });

  it('should convert to header object', () => {
    const csp = new CSPBuilder().defaultSrc("'self'");
    const headers = csp.toHeader();

    expect(headers['Content-Security-Policy']).toBeDefined();
    expect(headers['Content-Security-Policy']).toContain("default-src 'self'");
  });

  it('should support method chaining', () => {
    const csp = new CSPBuilder()
      .defaultSrc("'self'")
      .scriptSrc("'self'")
      .styleSrc("'self'")
      .imgSrc("'self'", 'data:')
      .upgradeInsecureRequests();

    expect(csp).toBeInstanceOf(CSPBuilder);
    const policy = csp.build();
    expect(policy).toContain("default-src 'self'");
  });
});
