import { describe, it, expect, beforeEach } from 'vitest';
import { PolicyEngine } from './policy-engine';
import type { Policy } from './types';

describe('ABAC Policy Engine', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  describe('evaluatePolicy', () => {
    it('evaluates allow policy that matches', async () => {
      const policy: Policy = {
        id: 'admin-access',
        name: 'Admin Access',
        effect: 'allow',
        rules: {
          attribute: 'user.role',
          operator: 'eq',
          value: 'admin',
        },
      };

      const result = await engine.evaluatePolicy(policy, {
        user: { role: 'admin' },
      });

      expect(result.granted).toBe(true);
      expect(result.decision).toBe('allow');
      expect(result.matchedPolicies).toContain('admin-access');
    });

    it('evaluates deny policy that matches', async () => {
      const policy: Policy = {
        id: 'guest-deny',
        name: 'Deny Guest',
        effect: 'deny',
        rules: {
          attribute: 'user.role',
          operator: 'eq',
          value: 'guest',
        },
      };

      const result = await engine.evaluatePolicy(policy, {
        user: { role: 'guest' },
      });

      expect(result.granted).toBe(false);
      expect(result.decision).toBe('deny');
    });

    it('returns not applicable when policy does not match', async () => {
      const policy: Policy = {
        id: 'admin-only',
        name: 'Admin Only',
        effect: 'allow',
        rules: {
          attribute: 'user.role',
          operator: 'eq',
          value: 'admin',
        },
      };

      const result = await engine.evaluatePolicy(policy, {
        user: { role: 'user' },
      });

      expect(result.granted).toBe(false);
      expect(result.decision).toBe('not_applicable');
      expect(result.matchedPolicies).toHaveLength(0);
    });

    it('evaluates complex policy with rule groups', async () => {
      const policy: Policy = {
        id: 'senior-admin',
        name: 'Senior Admin Access',
        effect: 'allow',
        rules: {
          operator: 'AND',
          rules: [
            { attribute: 'user.role', operator: 'eq', value: 'admin' },
            { attribute: 'user.yearsOfService', operator: 'gte', value: 5 },
          ],
        },
      };

      const result = await engine.evaluatePolicy(policy, {
        user: { role: 'admin', yearsOfService: 7 },
      });

      expect(result.granted).toBe(true);
      expect(result.decision).toBe('allow');
    });

    it('evaluates policy with environment attributes', async () => {
      const policy: Policy = {
        id: 'business-hours',
        name: 'Business Hours Only',
        effect: 'allow',
        rules: {
          attribute: 'environment.isBusinessHours',
          operator: 'eq',
          value: true,
        },
      };

      // Environment attributes are added automatically by the provider
      const result = await engine.evaluatePolicy(policy, {});

      expect(result.decision).toBe('allow'); // or 'not_applicable' depending on current time
    });

    it('uses cache for repeated evaluations', async () => {
      const policy: Policy = {
        id: 'cached-policy',
        name: 'Cached Policy',
        effect: 'allow',
        rules: {
          attribute: 'user.role',
          operator: 'eq',
          value: 'admin',
        },
      };

      const context = { user: { role: 'admin' } };

      const result1 = await engine.evaluatePolicy(policy, context, {
        useCache: true,
      });
      const result2 = await engine.evaluatePolicy(policy, context, {
        useCache: true,
      });

      expect(result1.granted).toBe(result2.granted);
      expect(result1.decision).toBe(result2.decision);
    });

    it('includes evaluation details when requested', async () => {
      const policy: Policy = {
        id: 'detailed-policy',
        name: 'Detailed Policy',
        effect: 'allow',
        rules: {
          operator: 'AND',
          rules: [
            { attribute: 'user.role', operator: 'eq', value: 'admin' },
            { attribute: 'user.active', operator: 'eq', value: true },
          ],
        },
      };

      const result = await engine.evaluatePolicy(
        policy,
        { user: { role: 'admin', active: true } },
        { includeDetails: true }
      );

      expect(result.details).toBeDefined();
      expect(result.details?.evaluatedRules).toBe(2);
      expect(result.details?.evaluationTime).toBeGreaterThanOrEqual(0);
    });
  });

  describe('evaluatePolicies', () => {
    const allowPolicy: Policy = {
      id: 'allow-admins',
      name: 'Allow Admins',
      effect: 'allow',
      rules: { attribute: 'user.role', operator: 'eq', value: 'admin' },
    };

    const denyPolicy: Policy = {
      id: 'deny-suspended',
      name: 'Deny Suspended Users',
      effect: 'deny',
      rules: { attribute: 'user.suspended', operator: 'eq', value: true },
    };

    it('uses deny-overrides algorithm by default', async () => {
      const result = await engine.evaluatePolicies([allowPolicy, denyPolicy], {
        user: { role: 'admin', suspended: true },
      });

      expect(result.granted).toBe(false);
      expect(result.decision).toBe('deny');
      expect(result.reason).toContain('deny-overrides');
    });

    it('uses allow-overrides algorithm', async () => {
      const result = await engine.evaluatePolicies(
        [allowPolicy, denyPolicy],
        { user: { role: 'admin', suspended: true } },
        { combiningAlgorithm: 'allow-overrides' }
      );

      expect(result.granted).toBe(true);
      expect(result.decision).toBe('allow');
      expect(result.reason).toContain('allow-overrides');
    });

    it('uses first-applicable algorithm', async () => {
      const result = await engine.evaluatePolicies(
        [allowPolicy, denyPolicy],
        { user: { role: 'admin', suspended: false } },
        { combiningAlgorithm: 'first-applicable' }
      );

      expect(result.granted).toBe(true);
      expect(result.decision).toBe('allow');
    });

    it('returns not applicable when no policies match', async () => {
      const result = await engine.evaluatePolicies([allowPolicy, denyPolicy], {
        user: { role: 'user', suspended: false },
      });

      expect(result.granted).toBe(false);
      expect(result.decision).toBe('not_applicable');
    });
  });

  describe('cache management', () => {
    it('clears cache', async () => {
      const policy: Policy = {
        id: 'test-policy',
        name: 'Test',
        effect: 'allow',
        rules: { attribute: 'user.role', operator: 'eq', value: 'admin' },
      };

      await engine.evaluatePolicy(policy, { user: { role: 'admin' } });
      engine.clearCache();

      // No direct way to verify cache is cleared without implementation details leaking
      // But subsequent evaluations should work fine
      const result = await engine.evaluatePolicy(policy, {
        user: { role: 'admin' },
      });
      expect(result.granted).toBe(true);
    });

    it('clears expired cache entries', async () => {
      const policy: Policy = {
        id: 'expiring-policy',
        name: 'Expiring',
        effect: 'allow',
        rules: { attribute: 'user.role', operator: 'eq', value: 'admin' },
      };

      // Evaluate with very short TTL
      await engine.evaluatePolicy(
        policy,
        { user: { role: 'admin' } },
        { cacheTTL: 1 }
      );

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 10));

      engine.clearExpiredCache();

      // Verify evaluation still works
      const result = await engine.evaluatePolicy(policy, {
        user: { role: 'admin' },
      });
      expect(result.granted).toBe(true);
    });
  });

  describe('attribute providers', () => {
    it('uses default user attribute provider', async () => {
      const policy: Policy = {
        id: 'user-attrs',
        name: 'User Attributes',
        effect: 'allow',
        rules: { attribute: 'user.id', operator: 'eq', value: 'user123' },
      };

      const result = await engine.evaluatePolicy(policy, {
        user: { id: 'user123' },
      });

      expect(result.granted).toBe(true);
    });

    it('uses provided user attributes', async () => {
      const policy: Policy = {
        id: 'custom-user-attrs',
        name: 'Custom User Attributes',
        effect: 'allow',
        rules: {
          attribute: 'user.department',
          operator: 'eq',
          value: 'engineering',
        },
      };

      const result = await engine.evaluatePolicy(policy, {
        user: { department: 'engineering' },
      });

      expect(result.granted).toBe(true);
    });

    it('registers custom attribute provider', async () => {
      engine.registerProvider({
        name: 'custom',
        getAttributes: async () => ({
          feature: 'enabled',
        }),
      });

      const policy: Policy = {
        id: 'custom-attrs',
        name: 'Custom Attributes',
        effect: 'allow',
        rules: {
          attribute: 'custom.feature',
          operator: 'eq',
          value: 'enabled',
        },
      };

      const result = await engine.evaluatePolicy(policy, {});

      expect(result.granted).toBe(true);
    });
  });
});
