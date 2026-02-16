/**
 * ABAC rule evaluator
 * Evaluates rules and rule groups against attribute context
 */

import type { Rule, RuleGroup, PolicyContext, AttributeValue } from './types';
import { evaluateComparison } from './operators';

/**
 * Get attribute value from context using path notation
 * Example: 'user.role' -> context.user?.role
 */
export function getAttributeValue(
  context: PolicyContext,
  path: string
): AttributeValue {
  const parts = path.split('.');
  let current: unknown = context;

  for (const part of parts) {
    if (current === null || typeof current !== 'object') {
      return null;
    }
    current = (current as Record<string, unknown>)[part];
  }

  // Return null instead of undefined for missing values
  return current === undefined ? null : (current as AttributeValue);
}

/**
 * Evaluate a single rule
 */
export function evaluateRule(rule: Rule, context: PolicyContext): boolean {
  const attributeValue = getAttributeValue(context, rule.attribute);
  return evaluateComparison(attributeValue, rule.operator, rule.value);
}

/**
 * Check if item is a rule (vs rule group)
 */
function isRule(item: Rule | RuleGroup): item is Rule {
  return 'attribute' in item && 'operator' in item;
}

/**
 * Evaluate a rule group
 */
export function evaluateRuleGroup(
  group: RuleGroup,
  context: PolicyContext
): boolean {
  const { operator, rules } = group;

  switch (operator) {
    case 'AND':
      return rules.every((rule) =>
        isRule(rule)
          ? evaluateRule(rule, context)
          : evaluateRuleGroup(rule, context)
      );

    case 'OR':
      return rules.some((rule) =>
        isRule(rule)
          ? evaluateRule(rule, context)
          : evaluateRuleGroup(rule, context)
      );

    case 'NOT': {
      // NOT operator should have exactly one rule/group
      if (rules.length !== 1) {
        throw new Error('NOT operator must have exactly one rule or group');
      }
      const firstRule = rules[0];
      if (!firstRule) {
        throw new Error('NOT operator requires one rule or group');
      }
      const result = isRule(firstRule)
        ? evaluateRule(firstRule, context)
        : evaluateRuleGroup(firstRule, context);
      return !result;
    }

    default:
      throw new Error(`Unknown logical operator: ${operator}`);
  }
}

/**
 * Evaluate rules (single rule or rule group)
 */
export function evaluateRules(
  rules: Rule | RuleGroup,
  context: PolicyContext
): boolean {
  if (isRule(rules)) {
    return evaluateRule(rules, context);
  }
  return evaluateRuleGroup(rules, context);
}

/**
 * Count total rules in a rule set (for metrics)
 */
export function countRules(rules: Rule | RuleGroup): number {
  if (isRule(rules)) {
    return 1;
  }

  return rules.rules.reduce((sum, rule) => sum + countRules(rule), 0);
}
