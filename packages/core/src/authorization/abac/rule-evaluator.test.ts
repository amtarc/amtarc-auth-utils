import { describe, it, expect } from 'vitest';
import {
  getAttributeValue,
  evaluateRule,
  evaluateRuleGroup,
  evaluateRules,
  countRules,
} from './rule-evaluator';
import type { Rule, RuleGroup, PolicyContext } from './types';

describe('ABAC Rule Evaluator', () => {
  describe('getAttributeValue', () => {
    it('gets nested attribute value', () => {
      const context: PolicyContext = {
        user: { role: 'admin', age: 30 },
        resource: { type: 'document', owner: 'user123' },
      };

      expect(getAttributeValue(context, 'user.role')).toBe('admin');
      expect(getAttributeValue(context, 'user.age')).toBe(30);
      expect(getAttributeValue(context, 'resource.owner')).toBe('user123');
    });

    it('returns null for missing attributes', () => {
      const context: PolicyContext = {
        user: { role: 'admin' },
      };

      expect(getAttributeValue(context, 'user.missing')).toBeNull();
      expect(getAttributeValue(context, 'missing.attribute')).toBeNull();
    });
  });

  describe('evaluateRule', () => {
    const context: PolicyContext = {
      user: { role: 'admin', departments: ['engineering', 'sales'] },
      resource: { type: 'document', sensitivity: 'high' },
    };

    it('evaluates simple equals rule', () => {
      const rule: Rule = {
        attribute: 'user.role',
        operator: 'eq',
        value: 'admin',
      };

      expect(evaluateRule(rule, context)).toBe(true);
    });

    it('evaluates in operator', () => {
      const rule: Rule = {
        attribute: 'resource.sensitivity',
        operator: 'in',
        value: ['high', 'critical'],
      };

      expect(evaluateRule(rule, context)).toBe(true);
    });

    it('evaluates contains operator', () => {
      const rule: Rule = {
        attribute: 'user.departments',
        operator: 'contains',
        value: 'engineering',
      };

      expect(evaluateRule(rule, context)).toBe(true);
    });

    it('returns false when rule does not match', () => {
      const rule: Rule = {
        attribute: 'user.role',
        operator: 'eq',
        value: 'user',
      };

      expect(evaluateRule(rule, context)).toBe(false);
    });
  });

  describe('evaluateRuleGroup', () => {
    const context: PolicyContext = {
      user: { role: 'admin', age: 30 },
      resource: { type: 'document' },
    };

    it('evaluates AND group (all must match)', () => {
      const group: RuleGroup = {
        operator: 'AND',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          { attribute: 'user.age', operator: 'gte', value: 18 },
        ],
      };

      expect(evaluateRuleGroup(group, context)).toBe(true);
    });

    it('evaluates AND group (one fails)', () => {
      const group: RuleGroup = {
        operator: 'AND',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          { attribute: 'user.age', operator: 'lt', value: 18 },
        ],
      };

      expect(evaluateRuleGroup(group, context)).toBe(false);
    });

    it('evaluates OR group (at least one matches)', () => {
      const group: RuleGroup = {
        operator: 'OR',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'superadmin' },
          { attribute: 'user.age', operator: 'gte', value: 18 },
        ],
      };

      expect(evaluateRuleGroup(group, context)).toBe(true);
    });

    it('evaluates OR group (all fail)', () => {
      const group: RuleGroup = {
        operator: 'OR',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'superadmin' },
          { attribute: 'user.age', operator: 'lt', value: 18 },
        ],
      };

      expect(evaluateRuleGroup(group, context)).toBe(false);
    });

    it('evaluates NOT group', () => {
      const group: RuleGroup = {
        operator: 'NOT',
        rules: [{ attribute: 'user.role', operator: 'eq', value: 'guest' }],
      };

      expect(evaluateRuleGroup(group, context)).toBe(true);
    });

    it('evaluates nested groups', () => {
      const group: RuleGroup = {
        operator: 'AND',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          {
            operator: 'OR',
            rules: [
              { attribute: 'user.age', operator: 'gte', value: 25 },
              { attribute: 'resource.type', operator: 'eq', value: 'public' },
            ],
          },
        ],
      };

      expect(evaluateRuleGroup(group, context)).toBe(true);
    });

    it('throws error for NOT with multiple rules', () => {
      const group: RuleGroup = {
        operator: 'NOT',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          { attribute: 'user.age', operator: 'gt', value: 18 },
        ],
      };

      expect(() => evaluateRuleGroup(group, context)).toThrow(
        'NOT operator must have exactly one'
      );
    });
  });

  describe('evaluateRules', () => {
    const context: PolicyContext = {
      user: { role: 'admin' },
    };

    it('evaluates single rule', () => {
      const rule: Rule = {
        attribute: 'user.role',
        operator: 'eq',
        value: 'admin',
      };

      expect(evaluateRules(rule, context)).toBe(true);
    });

    it('evaluates rule group', () => {
      const group: RuleGroup = {
        operator: 'AND',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          { attribute: 'user.role', operator: 'neq', value: 'guest' },
        ],
      };

      expect(evaluateRules(group, context)).toBe(true);
    });
  });

  describe('countRules', () => {
    it('counts single rule', () => {
      const rule: Rule = {
        attribute: 'user.role',
        operator: 'eq',
        value: 'admin',
      };

      expect(countRules(rule)).toBe(1);
    });

    it('counts rules in group', () => {
      const group: RuleGroup = {
        operator: 'AND',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          { attribute: 'user.age', operator: 'gt', value: 18 },
          { attribute: 'resource.type', operator: 'eq', value: 'document' },
        ],
      };

      expect(countRules(group)).toBe(3);
    });

    it('counts nested groups', () => {
      const group: RuleGroup = {
        operator: 'AND',
        rules: [
          { attribute: 'user.role', operator: 'eq', value: 'admin' },
          {
            operator: 'OR',
            rules: [
              { attribute: 'user.age', operator: 'gt', value: 18 },
              { attribute: 'resource.type', operator: 'eq', value: 'public' },
            ],
          },
        ],
      };

      expect(countRules(group)).toBe(3);
    });
  });
});
